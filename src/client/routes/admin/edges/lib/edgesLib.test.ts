import { describe, expect, it } from 'vitest';
import { ATTENTION_ACTIONS } from '../../../../../shared/contracts/edgeCodes';
import {
  ATTENTION_ACTION_PLAN,
  attentionActionLabel,
  attentionFactsLine,
  attentionHeading,
  attentionSubject,
  attentionTarget,
  type AttentionItem,
} from './attention';
import { filterCountries } from './countries';
import { auditDetailLine, displayValue, formatBytes, protocolLine } from './format';
import { parseBounded } from './number';
import { poolSlots, poolSummary, showsPublication } from './pool';
import { MAX_DESIRED_PUBLISHED } from '../../../../../shared/contracts/edgeLimits';
import {
  ROTATION_KIND_LABELS,
  ROTATION_TRIGGER_LABELS,
  standbyResultWords,
  stepStateTone,
} from './rotation';
import {
  EDGES_ROUTES,
  edgesPaths,
  legacyEdgesRedirect,
  resolveEdgesRoute,
  sectionTabOf,
  setupStepTarget,
} from './routes';
import { SETUP_STEP_IDS } from '../../../../../shared/contracts/edgeCodes';
import { resolveServersRoute } from '../../servers/lib/routes';
import { addTags, normalizeHostname, splitTags } from './tags';
import { actorLabel, subjectOf } from './timeline';
import type { TimelineRow } from './types';

const item = (over: Partial<AttentionItem>): AttentionItem => ({
  id: 'x:1',
  kind: 'pool_below_desired',
  severity: 'warning',
  relaySlug: 'relay-a',
  relayId: 'r1',
  edgeId: null,
  listenerKey: null,
  accountId: null,
  rotationId: null,
  code: null,
  facts: {},
  action: 'open_relay',
  since: null,
  ...over,
});

describe('resolveEdgesRoute / edgesPaths', () => {
  it('resolves every page', () => {
    expect(resolveEdgesRoute('/admin/edges')).toEqual({ page: 'home' });
    expect(resolveEdgesRoute('/admin/edges/')).toEqual({ page: 'home' });
    expect(resolveEdgesRoute('/admin/edges/nodes/node-a')).toEqual({
      page: 'node',
      slug: 'node-a',
    });
    expect(resolveEdgesRoute('/admin/edges/advanced')).toEqual({ page: 'advanced' });
    expect(resolveEdgesRoute('/admin/edges/advanced/origins')).toEqual({ page: 'overview' });
    expect(resolveEdgesRoute('/admin/edges/relays/relay-a')).toEqual({
      page: 'relay',
      slug: 'relay-a',
    });
    expect(resolveEdgesRoute('/admin/edges/providers')).toEqual({ page: 'providers' });
    expect(resolveEdgesRoute('/admin/edges/providers/abc123')).toEqual({
      page: 'provider',
      id: 'abc123',
    });
    expect(resolveEdgesRoute('/admin/edges/templates')).toEqual({ page: 'templates' });
    expect(resolveEdgesRoute('/admin/edges/probes')).toEqual({ page: 'probes' });
    expect(resolveEdgesRoute('/admin/edges/settings')).toEqual({ page: 'settings' });
  });
  it('falls through to not-found', () => {
    expect(resolveEdgesRoute('/admin/edges/nope')).toEqual({ page: 'not-found' });
    expect(resolveEdgesRoute('/admin/edges/relays')).toEqual({ page: 'not-found' });
    expect(resolveEdgesRoute('/admin/edges/relays/a/b')).toEqual({ page: 'not-found' });
    expect(resolveEdgesRoute('/admin/edges/nodes')).toEqual({ page: 'not-found' });
    // Moved: they resolve to nothing here, and legacyEdgesRedirect sends them on.
    expect(resolveEdgesRoute('/admin/edges/setup')).toEqual({ page: 'not-found' });
    expect(resolveEdgesRoute('/admin/edges/advanced/relays')).toEqual({ page: 'not-found' });
  });
  it('lights the header link of each page', () => {
    expect(sectionTabOf({ page: 'home' })).toBe('nodes');
    expect(sectionTabOf({ page: 'node', slug: 'a' })).toBe('nodes');
    expect(sectionTabOf({ page: 'providers' })).toBe('providers');
    expect(sectionTabOf({ page: 'provider', id: 'x' })).toBe('providers');
    for (const page of [
      'advanced',
      'overview',
      'templates',
      'probes',
      'settings',
      'names',
    ] as const)
      expect(sectionTabOf({ page })).toBe('advanced');
    expect(sectionTabOf({ page: 'family', slug: 'a' })).toBe('advanced');
    expect(sectionTabOf({ page: 'countries' })).toBe('countries');
    expect(sectionTabOf({ page: 'country', code: 'IR' })).toBe('countries');
    expect(resolveEdgesRoute('/admin/edges/countries')).toEqual({ page: 'countries' });
    expect(resolveEdgesRoute(edgesPaths.country('ir'))).toEqual({ page: 'country', code: 'IR' });
    expect(edgesPaths.country('ir', { node: 'node a' })).toBe(
      '/admin/edges/countries/IR?node=node+a',
    );
    expect(resolveEdgesRoute('/admin/edges/countries/iran')).toEqual({ page: 'not-found' });
    expect(resolveEdgesRoute('/admin/edges/names')).toEqual({ page: 'names' });
    expect(resolveEdgesRoute(edgesPaths.family('fam a'))).toEqual({
      page: 'family',
      slug: 'fam a',
    });
    expect(sectionTabOf({ page: 'relay', slug: 'a' })).toBe('advanced');
    // Find names (docs/edges.md "Finding names"): its own address, never a family slug.
    expect(resolveEdgesRoute(edgesPaths.findNames())).toEqual({ page: 'findNames' });
    expect(resolveEdgesRoute(edgesPaths.findNetwork('net a'))).toEqual({
      page: 'findNetwork',
      slug: 'net a',
    });
    expect(sectionTabOf({ page: 'findNames' })).toBe('advanced');
  });
  it('keeps every old address and builds the new ones', () => {
    expect(edgesPaths.overview()).toBe('/admin/edges/advanced/origins');
    expect(edgesPaths.overview({ new: '1' })).toBe('/admin/edges/advanced/origins?new=1');
    expect(edgesPaths.home()).toBe('/admin/edges');
    expect(edgesPaths.home({ protect: '1' })).toBe('/admin/edges?protect=1');
    expect(edgesPaths.home({ protect: '1', server: 'main', node: 'n 1', run: null })).toBe(
      '/admin/edges?protect=1&server=main&node=n+1',
    );
    expect(edgesPaths.node('a b', { test: 'e1' })).toBe('/admin/edges/nodes/a%20b?test=e1');
    expect(edgesPaths.advanced()).toBe('/admin/edges/advanced');
  });
  it('builds links that resolve back, with encoded params and clean defaults', () => {
    const href = edgesPaths.relay('a b/c', { tab: 'edges', edge: 'e1', rotation: null });
    expect(href).toBe('/admin/edges/relays/a%20b%2Fc?tab=edges&edge=e1');
    expect(resolveEdgesRoute(href.split('?')[0]!)).toEqual({ page: 'relay', slug: 'a b/c' });
  });
  it('redirects the moved pages: All origins and the old step-by-step wizard', () => {
    expect(legacyEdgesRedirect('/admin/edges/advanced/relays')).toBe(
      '/admin/edges/advanced/origins',
    );
    expect(legacyEdgesRedirect('/admin/edges/advanced/relays', '?filter=dark')).toBe(
      '/admin/edges/advanced/origins?filter=dark',
    );
    expect(legacyEdgesRedirect('/admin/edges/setup')).toBe('/admin/edges/advanced/origins');
    expect(legacyEdgesRedirect('/admin/edges/setup/', '?relay=relay-a&step=edge')).toBe(
      '/admin/edges/relays/relay-a',
    );
    for (const p of ['/admin/edges/advanced/relays', '/admin/edges/setup'])
      expect(resolveEdgesRoute(legacyEdgesRedirect(p)!.split('?')[0]!).page).not.toBe('not-found');
    for (const p of ['/admin/edges', '/admin/edges/advanced', '/admin/edges/relays/x'])
      expect(legacyEdgesRedirect(p)).toBeNull();
  });
  it('sends every readiness step to a page that does it', () => {
    for (const step of SETUP_STEP_IDS) {
      for (const slug of ['relay-a', null]) {
        const href = setupStepTarget(step, slug);
        expect(resolveEdgesRoute(href.split('?')[0]!).page).not.toBe('not-found');
      }
    }
    expect(setupStepTarget('edge', 'relay-a')).toBe('/admin/edges/relays/relay-a?tab=edges');
    expect(setupStepTarget('origin', null)).toBe('/admin/edges/advanced/origins?new=1');
    expect(setupStepTarget('account', 'relay-a')).toBe('/admin/edges/providers');
    expect(setupStepTarget('rendering', null)).toBe('/admin/edges/settings?section=rendering');
  });
  it('lists each pattern once', () => {
    const patterns = EDGES_ROUTES.map(([p]) => p);
    expect(new Set(patterns).size).toBe(patterns.length);
  });
});

describe('poolSlots', () => {
  it('marks wanted but empty slots as missing', () => {
    const slots = poolSlots({ publishedEdgeIds: ['e1', null], desired: 3 });
    expect(slots.map((s) => s.kind)).toEqual(['published', 'missing', 'missing']);
    expect(slots.map((s) => s.poolIndex)).toEqual([0, 1, 2]);
  });
  it('keeps a hole inside the pool but drops trailing vacant slots', () => {
    const slots = poolSlots({ publishedEdgeIds: ['e1', null, 'e3', null], desired: 1 });
    expect(slots.map((s) => s.kind)).toEqual(['published', 'vacant', 'published']);
    expect(slots[2]!.surplus).toBe(true);
    expect(slots[0]!.surplus).toBe(false);
  });
  it('appends standbys (ids or a count) and draining', () => {
    const byId = poolSlots({ publishedEdgeIds: ['e1'], desired: 1, standbys: ['s1'], draining: 2 });
    expect(byId.map((s) => s.kind)).toEqual(['published', 'standby', 'draining', 'draining']);
    expect(byId[1]!.edgeId).toBe('s1');
    const byCount = poolSlots({ publishedEdgeIds: [], desired: 0, standbys: 2 });
    expect(byCount.map((s) => s.kind)).toEqual(['standby', 'standby']);
    expect(byCount[0]!.edgeId).toBeNull();
  });
  it('survives nonsense input', () => {
    expect(poolSlots({ publishedEdgeIds: [], desired: -3, standbys: NaN, draining: -1 })).toEqual(
      [],
    );
    expect(poolSlots({ publishedEdgeIds: [], desired: 1e9 }).length).toBe(MAX_DESIRED_PUBLISHED);
  });
  it('shows every slot of a pool at the published-pool cap', () => {
    const ids = Array.from({ length: MAX_DESIRED_PUBLISHED }, (_, i) => `e${i}`);
    const input = { publishedEdgeIds: ids, desired: MAX_DESIRED_PUBLISHED };
    const slots = poolSlots(input);
    expect(slots).toHaveLength(MAX_DESIRED_PUBLISHED);
    expect(slots.every((s) => s.kind === 'published')).toBe(true);
    expect(slots[MAX_DESIRED_PUBLISHED - 1]?.edgeId).toBe(`e${MAX_DESIRED_PUBLISHED - 1}`);
    expect(poolSummary(input)).toBe(
      `${MAX_DESIRED_PUBLISHED} of ${MAX_DESIRED_PUBLISHED} published`,
    );
    const wanted = poolSlots({ publishedEdgeIds: ['e0'], desired: 40 });
    expect(wanted.filter((s) => s.kind === 'missing')).toHaveLength(39);
    expect(poolSummary({ publishedEdgeIds: ['e0'], desired: 40 })).toBe('1 of 40 published');
  });
  it('summarises in words', () => {
    expect(poolSummary({ publishedEdgeIds: ['a', null, 'b'], desired: 3 })).toBe(
      '2 of 3 published',
    );
    expect(poolSummary({ publishedEdgeIds: ['a'], desired: 2, standbys: ['s'], draining: 1 })).toBe(
      '1 of 2 published, 1 standby, 1 draining',
    );
    expect(poolSummary({ publishedEdgeIds: [], desired: 1, standbys: 2 })).toBe(
      '0 of 1 published, 2 standbys',
    );
  });
});

describe('attention', () => {
  it('plans every action literal', () => {
    for (const a of ATTENTION_ACTIONS) expect(ATTENTION_ACTION_PLAN[a]).toBeDefined();
  });
  it('gives every action a target inside the section (a node page lives under Servers)', () => {
    for (const action of ATTENTION_ACTIONS) {
      const href = attentionTarget(
        item({ action, edgeId: 'e1', rotationId: 'rot1', listenerKey: 'main', accountId: 'acc1' }),
      );
      if (action === 'open_node') {
        expect(resolveServersRoute(href.split('?')[0]!).page).not.toBe('not-found');
        continue;
      }
      // Turning a mode on is the Connection modes page's job.
      if (action === 'open_modes') {
        expect(href).toBe('/admin/connection-modes');
        continue;
      }
      expect(href.startsWith('/admin/edges')).toBe(true);
      expect(resolveEdgesRoute(href.split('?')[0]!).page).not.toBe('not-found');
    }
  });
  it('links an enrolled node to the protect sheet or to its Servers page', () => {
    const facts = { serverSlug: 'panel-a', nodeUuid: 'uuid-1', node: 'node-one' };
    expect(attentionTarget(item({ action: 'protect_node', relaySlug: null, facts }))).toBe(
      '/admin/edges?protect=1&server=panel-a&node=uuid-1',
    );
    // An origin already covers it: Protect again lives on its node page.
    expect(attentionTarget(item({ action: 'protect_node', facts }))).toBe(
      '/admin/edges/nodes/relay-a',
    );
    expect(attentionTarget(item({ action: 'open_node', facts }))).toBe(
      '/admin/servers/nodes/uuid-1?instance=panel-a',
    );
    expect(attentionTarget(item({ action: 'open_node', facts: {} }))).toBe('/admin/servers');
  });
  it('routes the navigation actions as documented', () => {
    expect(attentionTarget(item({ action: 'open_setup' }))).toBe('/admin/edges/relays/relay-a');
    expect(attentionTarget(item({ action: 'resolve_quarantine', rotationId: 'rot1' }))).toBe(
      '/admin/edges/relays/relay-a?tab=rotations&rotation=rot1',
    );
    expect(attentionTarget(item({ action: 'look_at_host', listenerKey: 'main' }))).toBe(
      '/admin/edges/relays/relay-a?tab=listeners&listener=main',
    );
    expect(attentionTarget(item({ action: 'provision' }))).toBe(
      '/admin/edges/relays/relay-a?tab=edges',
    );
    expect(attentionTarget(item({ action: 'open_edge', edgeId: 'e1' }))).toBe(
      '/admin/edges/relays/relay-a?tab=edges&edge=e1',
    );
    expect(attentionTarget(item({ action: 'open_account', accountId: 'acc1' }))).toBe(
      '/admin/edges/providers/acc1',
    );
    expect(attentionTarget(item({ action: 'thaw', relaySlug: null }))).toBe(
      '/admin/edges/settings?section=maintenance',
    );
  });
  it('falls back to the home without a origin', () => {
    expect(attentionTarget(item({ action: 'open_relay', relaySlug: null }))).toBe('/admin/edges');
    expect(attentionTarget(item({ action: 'open_account' }))).toBe('/admin/edges/providers');
  });
  it('sends the endpoint test and go-live to the node page', () => {
    expect(attentionTarget(item({ action: 'verify_endpoint', edgeId: 'e1' }))).toBe(
      '/admin/edges/nodes/relay-a?test=e1',
    );
    expect(attentionTarget(item({ action: 'require_edges' }))).toBe('/admin/edges/nodes/relay-a');
    // Both are handled by the host page when it offers `onAction` (the card opens in place).
    expect(ATTENTION_ACTION_PLAN.verify_endpoint).toEqual({ type: 'call', confirm: null });
    expect(ATTENTION_ACTION_PLAN.require_edges).toEqual({ type: 'call', confirm: null });
  });
  it('confirms the billable and disruptive calls only', () => {
    const confirmed = ATTENTION_ACTIONS.filter((a) => {
      const p = ATTENTION_ACTION_PLAN[a];
      return p.type === 'call' && p.confirm !== null;
    });
    // A rebalance unpublishes an edge members may be using: disruptive, so confirmed.
    expect(confirmed.sort()).toEqual(['provision', 'publish', 'rebalance', 'rotate', 'thaw']);
  });
  it('renders only known facts', () => {
    expect(
      attentionFactsLine(
        item({ facts: { published: 1, desired: 3, countries: ['IR', 'CN'], secretish: 'x' } }),
      ),
    ).toBe('1 of 3 published · in IR, CN');
    expect(attentionFactsLine(item({ facts: { ageMs: 120_000 } }))).toBe('for 2 min');
    // A per-location trust item names its location when the account has several.
    expect(attentionFactsLine(item({ facts: { name: 'acct-a', location: 'Region B' } }))).toBe(
      'Account acct-a, Region B',
    );
    expect(attentionFactsLine(item({ facts: { name: 'acct-a' } }))).toBe('Account acct-a');
    // A thin family is named, with how many of its names qualify.
    expect(
      attentionFactsLine(item({ facts: { family: 'fam-a', familyLabel: 'Fam A', qualifying: 1 } })),
    ).toBe('Family Fam A · 1 name qualifies');
    expect(attentionFactsLine(item({ facts: { family: 'fam-b', qualifying: 0 } }))).toBe(
      'Family fam-b · 0 names qualify',
    );
    // A REALITY transport that refuses clients: which (the row words the rest).
    expect(attentionFactsLine(item({ facts: { count: 1, refuses: ['singbox', 'mihomo'] } }))).toBe(
      '1 affected · Refuses sing-box and Mihomo',
    );
    // A failed run's kind is its title, never a "Provision run" fact.
    expect(attentionFactsLine(item({ facts: { kind: 'provision', phase: 'failed' } }))).toBe('');
    expect(attentionSubject(item({ listenerKey: 'main' }))).toBe('Origin relay-a, listener main');
    expect(attentionSubject(item({ relaySlug: null }))).toBe('');
  });
});

describe('copy hygiene', () => {
  const strings: string[] = [
    ...Object.values(ROTATION_KIND_LABELS),
    ...Object.values(ROTATION_TRIGGER_LABELS),
    ...ATTENTION_ACTIONS.flatMap((a) => {
      const p = ATTENTION_ACTION_PLAN[a];
      return p.type === 'call' && p.confirm
        ? [p.confirm.title, p.confirm.body, p.confirm.confirmLabel]
        : [];
    }),
    parseBounded('', {}).ok ? '' : 'Enter a number.',
  ];
  it('has no em-dash and no API path', () => {
    for (const s of strings) {
      expect(s).not.toContain('—');
      expect(s).not.toContain('/api/');
    }
  });
});

describe('format', () => {
  it('writes the protocol line', () => {
    expect(protocolLine({ protocol: 'vless', streamTransport: 'raw', security: 'reality' })).toBe(
      'VLESS · raw · REALITY',
    );
    expect(protocolLine({ protocol: 'trojan', streamTransport: 'ws', security: 'tls' })).toBe(
      'Trojan · WebSocket · TLS',
    );
  });
  it('formats bytes and values', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBytes(null)).toBe('');
    expect(displayValue(true)).toBe('Yes');
    expect(displayValue(null)).toBe('');
    expect(displayValue(['a', 'b'])).toBe('a, b');
    expect(displayValue({ a: 1 })).toBe('{"a":1}');
  });
  it('reads only known audit payload keys', () => {
    expect(auditDetailLine({ code: 'edge.cooldown', token: 'nope' })).toBe('In cooldown');
    expect(auditDetailLine({ changedKeys: ['a', 'b'] })).toBe('changed a, b');
    // A failed run: its reason, then the provider's own words.
    expect(
      auditDetailLine({ code: 'step_retries_exhausted', answer: '1 input is not valid' }),
    ).toBe('Step retries exhausted · The provider answered: 1 input is not valid.');
    // Advanced keeps the key; the simple face names the listener in words.
    expect(auditDetailLine({ listenerKey: 'freedomrea55ng1t' })).toBe('listener freedomrea55ng1t');
    expect(auditDetailLine({ listenerKey: 'freedomrea55ng1t' }, () => 'VLESS + REALITY')).toBe(
      'VLESS + REALITY',
    );
    expect(auditDetailLine(null)).toBe('');
    expect(auditDetailLine('x')).toBe('');
  });
});

describe('parseBounded', () => {
  it('accepts in-range integers', () => {
    expect(parseBounded('15', { min: 1, max: 60 })).toEqual({ ok: true, value: 15 });
  });
  it('rejects empty, fractional and out-of-range input in words', () => {
    expect(parseBounded(' ', {})).toEqual({ ok: false, message: 'Enter a number.' });
    expect(parseBounded('1.5', {})).toEqual({ ok: false, message: 'Enter a whole number.' });
    expect(parseBounded('1.5', { integer: false })).toEqual({ ok: true, value: 1.5 });
    expect(parseBounded('0', { min: 1 })).toEqual({ ok: false, message: 'Must be at least 1.' });
    expect(parseBounded('61', { max: 60 })).toEqual({ ok: false, message: 'Must be at most 60.' });
  });
});

describe('tags', () => {
  it('splits on commas, spaces and semicolons', () => {
    expect(splitTags(' a, b;c\n d ')).toEqual(['a', 'b', 'c', 'd']);
  });
  it('normalises, de-duplicates, caps and reports rejects', () => {
    const r = addTags(['one.example'], 'ONE.example two.example bad_name', {
      normalize: normalizeHostname,
    });
    expect(r.next).toEqual(['one.example', 'two.example']);
    expect(r.rejected).toEqual(['bad_name']);
    expect(
      addTags(['a.example'], 'b.example c.example', { normalize: normalizeHostname, max: 2 }),
    ).toEqual({
      next: ['a.example', 'b.example'],
      rejected: ['c.example'],
    });
  });
  it('validates hostnames', () => {
    expect(normalizeHostname('Front.Example.')).toBe('front.example');
    expect(normalizeHostname('localhost')).toBeNull();
    expect(normalizeHostname('-a.example')).toBeNull();
  });
});

describe('countries', () => {
  const opts = [
    { code: 'IR', name: 'Iran' },
    { code: 'IE', name: 'Ireland' },
    { code: 'CI', name: 'Ivory Coast' },
  ];
  it('ranks code prefixes before name matches', () => {
    expect(filterCountries(opts, 'i').map((o) => o.code)).toEqual(['IR', 'IE', 'CI']);
    expect(filterCountries(opts, 'ire').map((o) => o.code)).toEqual(['IE']);
    expect(filterCountries(opts, '').length).toBe(3);
  });
});

describe('timeline', () => {
  const row = (action: string, over: Partial<TimelineRow> = {}): TimelineRow => ({
    id: '1',
    actorType: 'system',
    actorId: null,
    action,
    targetType: null,
    targetId: null,
    payload: null,
    requestId: null,
    createdAt: '2026-01-01T00:00:00.000Z',
    ...over,
  });
  it('prefers the server subject and infers one otherwise', () => {
    expect(subjectOf(row('edge.published', { subject: 'relay' }))).toBe('relay');
    expect(subjectOf(row('probe.verdict'))).toBe('probe');
    expect(subjectOf(row('relay.host.created'))).toBe('listener');
    expect(subjectOf(row('relay.update'))).toBe('relay');
    expect(subjectOf(row('admin.edge.rotate'))).toBe('rotation');
    expect(subjectOf(row('edge.published'))).toBe('edge');
    expect(subjectOf(row('something.else'))).toBe('other');
  });
  it('names the actor', () => {
    expect(actorLabel(row('x', { actorType: 'admin' }))).toBe('An admin');
  });
  it('tones provider step states', () => {
    expect(stepStateTone('done')).toBe('success');
    expect(stepStateTone('FAILED')).toBe('danger');
    expect(stepStateTone('whatever')).toBe('neutral');
  });
  it('a publish the pool held back is toasted with why and the ways on', () => {
    expect(standbyResultWords('pool_reserved')).toMatch(
      /^The edge stayed a standby: the free pool slot is held .* Replace a published edge with it, or remove that location/,
    );
    expect(standbyResultWords('pool_full')).toMatch(/every pool slot is taken/);
    for (const code of ['pool_reserved', 'pool_full'] as const)
      expect(standbyResultWords(code)).not.toMatch(/—|_|\/api\//);
  });
});

describe('showsPublication', () => {
  it('hides the publication badge of an edge being destroyed or gone', () => {
    expect(showsPublication({ status: 'destroying' })).toBe(false);
    expect(showsPublication({ status: 'destroyed' })).toBe(false);
    for (const status of ['active', 'draining', 'provisioning', 'failed', 'needs_operator'])
      expect(showsPublication({ status })).toBe(true);
  });
});

describe('a failed run in the attention list', () => {
  const failed = (facts: Record<string, unknown>) =>
    ({
      id: 'rotation_failed:r1',
      kind: 'rotation_failed',
      severity: 'warning',
      relaySlug: 'node-one',
      relayId: 'o1',
      edgeId: null,
      listenerKey: null,
      accountId: null,
      rotationId: 'r1',
      code: 'step_retries_exhausted',
      facts,
      action: 'open_relay',
      since: null,
    }) as AttentionItem;
  it('is named by what it was, and its button opens the run', () => {
    expect(attentionHeading(failed({ kind: 'provision', spare: true }), true)).toEqual({
      label: 'Adding a spare failed',
      explain: 'A new spare address for this protected node could not be created.',
      final: true,
    });
    // A replacement keeps the kind's own copy (worded by the screen).
    expect(attentionHeading(failed({ kind: 'replace' }), true)).toMatchObject({
      label: 'Rotation failed',
      final: false,
    });
    expect(attentionActionLabel(failed({ kind: 'provision' }), true)).toBe('Open the run');
    expect(attentionActionLabel(failed({ kind: 'provision' }), false)).toBe('Open run');
    expect(attentionTarget(failed({ kind: 'provision' }))).toContain('rotation=r1');
  });
});

describe('an unused operator front row', () => {
  const row = (facts: Record<string, unknown>) =>
    ({ ...item({ kind: 'front_host_unused', severity: 'info' }), facts }) as AttentionItem;
  it("says how many of the node's keys still hold it, and how a member moves over", () => {
    const h = attentionHeading(
      row({ count: 3, remarks: ['lb-a', 'lb-b', 'lb-c'], staleKeys: 1204, keys: 2050 }),
      true,
    );
    expect(h).toMatchObject({ label: 'Old front no longer used', final: true });
    expect(h.explain).toMatch(
      /1,204 of the node's 2,050 keys have not fetched since the node went live, so those apps still connect through it until the member updates the subscription in the app\./,
    );
    expect(h.explain).toMatch(/Once its traffic stops, delete it at its provider/);
    expect(attentionHeading(row({ count: 1, staleKeys: 1, keys: 1 }), true).explain).toMatch(
      /1 of the node's 1 key has not fetched/,
    );
  });
  it('says when every key has fetched since, and still asks for the traffic to stop', () => {
    const explain = attentionHeading(row({ count: 1, staleKeys: 0, keys: 12 }), true).explain;
    expect(explain).toMatch(
      /Every key on the node has fetched its subscription since the node went live, but an app sharing a key/,
    );
    expect(explain).toMatch(/Once its traffic stops, delete it at its provider/);
  });
  it("falls back to the kind's words before a count", () => {
    expect(attentionHeading(row({ count: 1, remarks: ['lb-a'] }), true)).toMatchObject({
      final: false,
    });
  });
});

describe('a REALITY refusal row', () => {
  const row = (facts: Record<string, unknown>) =>
    ({ ...item({ kind: 'reality_refuses_clients' }), facts }) as AttentionItem;
  it('is worded from the verdict it carries: each reason with its own fix', () => {
    const h = attentionHeading(
      row({
        count: 1,
        refuses: ['singbox', 'mihomo'],
        transports: [
          {
            tag: 'VLESS_IN',
            refusal: {
              refuses: ['singbox', 'mihomo'],
              reasons: [
                { cause: 'min_above', families: ['singbox'] },
                { cause: 'max_below', families: ['mihomo'] },
              ],
              xrayVersion: '26.6.27',
              minClientVer: '1.8.2',
              maxClientVer: '1.8.1',
            },
          },
        ],
      }),
      true,
    );
    expect(h.final).toBe(true);
    expect(h.label).toBe('REALITY refuses sing-box or Mihomo');
    expect(h.explain).toMatch(/^VLESS_IN: Refuses sing-box .* and Mihomo .* clients\./);
    expect(h.explain).toMatch(/minClientVer is 1\.8\.2, above what sing-box sends \(1\.8\.1\)/);
    expect(h.explain).toMatch(/Set "minClientVer" to "1\.8\.1"/);
    expect(h.explain).toMatch(/Remove "maxClientVer"/);
  });
  it("falls back to the kind's words when it carries no verdict", () => {
    expect(attentionHeading(row({ count: 1 }), true)).toMatchObject({ final: false });
  });
});
