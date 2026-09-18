import { describe, expect, it } from 'vitest';
import { ATTENTION_ACTIONS } from '../../../../../shared/contracts/edgeCodes';
import {
  ATTENTION_ACTION_PLAN,
  attentionFactsLine,
  attentionSubject,
  attentionTarget,
  type AttentionItem,
} from './attention';
import { filterCountries } from './countries';
import { auditDetailLine, displayValue, formatBytes, protocolLine } from './format';
import { parseBounded } from './number';
import { poolSlots, poolSummary } from './pool';
import { ROTATION_KIND_LABELS, ROTATION_TRIGGER_LABELS, stepStateTone } from './rotation';
import { EDGES_ROUTES, edgesPaths, resolveEdgesRoute } from './routes';
import { addTags, normalizeCountry, normalizeHostname, splitTags } from './tags';
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
    expect(resolveEdgesRoute('/admin/edges')).toEqual({ page: 'overview' });
    expect(resolveEdgesRoute('/admin/edges/')).toEqual({ page: 'overview' });
    expect(resolveEdgesRoute('/admin/edges/setup')).toEqual({ page: 'setup' });
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
  });
  it('builds links that resolve back, with encoded params and clean defaults', () => {
    const href = edgesPaths.relay('a b/c', { tab: 'edges', edge: 'e1', rotation: null });
    expect(href).toBe('/admin/edges/relays/a%20b%2Fc?tab=edges&edge=e1');
    expect(resolveEdgesRoute(href.split('?')[0]!)).toEqual({ page: 'relay', slug: 'a b/c' });
    expect(edgesPaths.setup({ relay: null })).toBe('/admin/edges/setup');
    expect(edgesPaths.setup({ relay: 'relay-a', step: 'edge' })).toBe(
      '/admin/edges/setup?relay=relay-a&step=edge',
    );
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
    expect(poolSlots({ publishedEdgeIds: [], desired: 1e9 }).length).toBe(24);
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
  it('gives every action a target inside the section', () => {
    for (const action of ATTENTION_ACTIONS) {
      const href = attentionTarget(
        item({ action, edgeId: 'e1', rotationId: 'rot1', listenerKey: 'main', accountId: 'acc1' }),
      );
      expect(href.startsWith('/admin/edges')).toBe(true);
      expect(resolveEdgesRoute(href.split('?')[0]!).page).not.toBe('not-found');
    }
  });
  it('routes the navigation actions as documented', () => {
    expect(attentionTarget(item({ action: 'open_setup' }))).toBe(
      '/admin/edges/setup?relay=relay-a',
    );
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
  it('falls back to the overview without a relay', () => {
    expect(attentionTarget(item({ action: 'open_relay', relaySlug: null }))).toBe('/admin/edges');
    expect(attentionTarget(item({ action: 'open_account' }))).toBe('/admin/edges/providers');
  });
  it('confirms the billable and disruptive calls only', () => {
    const confirmed = ATTENTION_ACTIONS.filter((a) => {
      const p = ATTENTION_ACTION_PLAN[a];
      return p.type === 'call' && p.confirm !== null;
    });
    expect(confirmed.sort()).toEqual(['provision', 'publish', 'rotate', 'thaw']);
  });
  it('renders only known facts', () => {
    expect(
      attentionFactsLine(
        item({ facts: { published: 1, desired: 3, countries: ['IR', 'CN'], secretish: 'x' } }),
      ),
    ).toBe('1 of 3 published · in IR, CN');
    expect(attentionFactsLine(item({ facts: { ageMs: 120_000 } }))).toBe('for 2 min');
    expect(attentionSubject(item({ listenerKey: 'main' }))).toBe('Relay relay-a, listener main');
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
    expect(addTags(['IR'], 'cn ru', { normalize: normalizeCountry, max: 2 })).toEqual({
      next: ['IR', 'CN'],
      rejected: ['ru'],
    });
  });
  it('validates hostnames and country codes', () => {
    expect(normalizeHostname('Front.Example.')).toBe('front.example');
    expect(normalizeHostname('localhost')).toBeNull();
    expect(normalizeHostname('-a.example')).toBeNull();
    expect(normalizeCountry('ir')).toBe('IR');
    expect(normalizeCountry('IRN')).toBeNull();
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
});
