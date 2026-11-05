/**
 * Addresses only for some countries (docs/edges.md "Addresses only for some
 * countries"): the audience at first publication (the lanes' taint rule, a
 * replacement's), who may be handed a contained address (fail closed), where
 * automatic selection may put an address, and that the assignment and the
 * detector's proof agree on it.
 */
import { describe, expect, test } from 'vitest';
import { audienceAtPublish, covers, inAudience, locationTakes, onlyCodesOf } from './audience';
import {
  assignEndpoints,
  fnv1a32,
  steeringAvoids,
  type AssignOptions,
  type PublishedEdge,
} from './assignment';
import type { ListenerProto } from './protocols';

const SINCE = 1_000;
const ONLY = { codes: ['RU', 'IR'], only: { since: SINCE } };
const fresh = { _creationTime: SINCE + 1, resources: [{ ownership: 'created' }] };

describe('the audience at first publication', () => {
  test('a clean address at an only location takes its countries, sorted', () => {
    expect(audienceAtPublish({ edge: fresh, location: ONLY, seenBefore: false })).toEqual({
      kind: 'contained',
      audience: ['IR', 'RU'],
    });
  });

  test('not only (or no countries): everyone', () => {
    for (const location of [null, { codes: ['IR'] }, { codes: [], only: { since: SINCE } }])
      expect(audienceAtPublish({ edge: fresh, location, seenBefore: false })).toEqual({
        kind: 'everyone',
      });
  });

  test('the taint rule: made before the switch, published before, adopted, seen before', () => {
    const refused = { kind: 'refused', reason: 'audience_tainted' };
    for (const edge of [
      { _creationTime: SINCE, resources: [] },
      { ...fresh, publishedAt: 5 },
      { ...fresh, resources: [{ ownership: 'adopted' }] },
      { ...fresh, resources: [] },
    ])
      expect(audienceAtPublish({ edge, location: ONLY, seenBefore: false })).toEqual(refused);
    expect(audienceAtPublish({ edge: fresh, location: ONLY, seenBefore: true })).toEqual(refused);
  });

  test("a replacement: an everyone address's never gets an audience; a contained one's takes it when covered", () => {
    const at = (replacing: { audience?: string[] }) =>
      audienceAtPublish({ edge: fresh, location: ONLY, seenBefore: false, replacing });
    expect(at({})).toEqual({ kind: 'refused', reason: 'audience_replaces_everyone' });
    expect(at({ audience: ['IR'] })).toEqual({ kind: 'contained', audience: ['IR', 'RU'] });
    expect(at({ audience: ['CN'] })).toEqual({
      kind: 'refused',
      reason: 'audience_replaces_everyone',
    });
  });
});

describe('who may be handed one', () => {
  test('a member in it; nobody else, no country included', () => {
    expect(inAudience(['IR', 'RU'], 'IR')).toBe(true);
    expect(inAudience(['IR', 'RU'], 'CN')).toBe(false);
    expect(inAudience(['IR'], null)).toBe(false);
    expect(inAudience(undefined, null)).toBe(true);
    expect(inAudience([], 'DE')).toBe(true);
  });

  test('automatic selection: an only location takes a covered contained target or its own count fill', () => {
    expect(locationTakes(ONLY, {})).toBe(false);
    expect(locationTakes(ONLY, { audience: ['IR'] })).toBe(true);
    expect(locationTakes(ONLY, { audience: ['IR', 'CN'] })).toBe(false);
    expect(locationTakes(ONLY, { countFillHere: true })).toBe(true);
    expect(locationTakes({ codes: ['IR'] }, {})).toBe(true);
    expect(onlyCodesOf(ONLY)).toEqual(['IR', 'RU']);
    expect(covers(['IR', 'RU'], ['RU'])).toBe(true);
  });
});

const REALITY: ListenerProto = { protocol: 'vless', streamTransport: 'raw', security: 'reality' };
const keyOf = (i: number) =>
  (fnv1a32(`member:${i}`) >>> 0).toString(16).padStart(8, '0') + 'cd'.repeat(28);
const edge = (id: string, i: number, over: Partial<PublishedEdge> = {}): PublishedEdge => ({
  edgeId: id,
  poolIndex: i,
  provider: i % 2 ? 'p2' : 'p1',
  listenerId: 'l1',
  listenerKey: 'a1',
  matchRule: { kind: 'remark', remark: 'r' },
  edgePort: 443,
  layer: 'l4',
  addresses: { v4: `203.0.113.${i + 1}` },
  proto: REALITY,
  serverNames: ['a.example', 'b.example'].map((sni) => ({ sni, status: 'active' as const })),
  ...over,
});

describe('the assignment', () => {
  const everyone = [edge('e0', 0), edge('e1', 1)];
  const contained = edge('only-ir', 2, { audience: ['IR'] });
  const pool = [...everyone, contained];
  const base: AssignOptions = {
    now: 1,
    preferDistinctProviders: true,
    includeBackup: true,
    edgePick: 'hrw1',
  };
  const handed = (opts: AssignOptions) => {
    const seen = new Set<string>();
    for (let i = 0; i < 300; i++) {
      const a = assignEndpoints(keyOf(i), pool, opts);
      for (const e of [a.primary, a.backup]) if (e) seen.add(e.edge.edgeId);
    }
    return seen;
  };

  test('no country, another country, or steering off: never handed; a member there: yes', () => {
    expect(handed(base).has('only-ir')).toBe(false);
    expect(
      handed({ ...base, edgeCountry: 'RU', where: { country: 'RU', curated: ['IR', 'RU'] } }).has(
        'only-ir',
      ),
    ).toBe(false);
    expect(handed({ ...base, avoidBlockedIn: ['IR'] }).has('only-ir')).toBe(false);
    expect(
      handed({ ...base, edgeCountry: 'IR', where: { country: 'IR', curated: ['IR', 'RU'] } }).has(
        'only-ir',
      ),
    ).toBe(true);
  });

  test('it keeps its seat: members without it are handed exactly what they were without it in the pool', () => {
    const withIt = (i: number) => assignEndpoints(keyOf(i), pool, base);
    const without = (i: number) =>
      assignEndpoints(keyOf(i), [...everyone, { ...contained, eligible: false }], base);
    for (let i = 0; i < 200; i++) {
      expect(withIt(i).primary?.edge.edgeId).toBe(without(i).primary?.edge.edgeId);
      expect(withIt(i).backup?.edge.edgeId).toBe(without(i).backup?.edge.edgeId);
    }
  });

  test("the detector's proof: an address a member there may not be handed is no way around", () => {
    const paths = [{ format: 'links' as const, canEmitV6: false }];
    const blocked = edge('blocked', 0, { blockedIn: ['RU'] });
    // The only other address is contained to Iran: no way around it for Russia.
    expect(
      steeringAvoids(blocked, [blocked, edge('x', 1, { audience: ['IR'] })], 'RU', paths, [
        'IR',
        'RU',
      ]),
    ).toBe(false);
    expect(steeringAvoids(blocked, [blocked, edge('x', 1)], 'RU', paths, ['IR', 'RU'])).toBe(true);
    // For mirrors without a choice, a contained address is never a way around either.
    expect(
      steeringAvoids(
        blocked,
        [blocked, edge('x', 1, { audience: ['RU'] })],
        'RU',
        paths,
        ['IR', 'RU'],
        {
          universal: true,
        },
      ),
    ).toBe(false);
  });
});
