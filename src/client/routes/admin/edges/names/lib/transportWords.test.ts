/**
 * A transport's names on a node's page: one next step at a time, a status
 * line that counts what this node's members get, the reason a suggestion is
 * worth adding, and the "Needs you" lines. No codes, no em-dashes.
 */
import { describe, expect, test } from 'vitest';
import type {
  SniCandidateRow,
  SniTransport,
  SniTransportsView,
} from '../../../../../../shared/contracts/sni';
import {
  STEP_BUTTON,
  addedWords,
  lookedWords,
  managedWords,
  namesNeedsYou,
  namesStatus,
  namesStep,
  nodeLineWords,
  provenWords,
  testNameChoice,
  sendPlanWords,
  stepWords,
  suggestionReason,
  type NamesStep,
} from './transportWords';

const NODE = 'n-1';
const on: SniTransportsView['switches'] = {
  names: true,
  findNames: true,
  backendChanges: true,
  backendSetUp: true,
};
const counts = {
  inUse: 4,
  waitingTest: 0,
  toSend: 0,
  idle: 0,
  checking: 0,
  failing: 0,
  off: 0,
};

function transport(o: Partial<SniTransport> = {}, c: Partial<typeof counts> = {}): SniTransport {
  return {
    transportUuid: 't-1',
    tag: 'VLESS_REALITY',
    profileUuid: 'p-1',
    profileName: 'Main',
    port: 443,
    coverSite: 'site.example:443',
    listed: 4,
    profileNodes: [{ nodeUuid: NODE, name: 'node-one' }],
    list: {
      slug: 'vless-reality',
      label: 'VLESS_REALITY names',
      enabled: true,
      bindingId: 'b-1',
      counts: { ...counts, ...c },
      suggestions: 0,
    },
    send: { rolloutId: 'r-1', generation: 2, phase: 'panel_confirmed', witness: null },
    nodes: [
      {
        relaySlug: 'node-one',
        nodeUuid: NODE,
        nodeName: 'node-one',
        inUse: 4,
        waitingTest: 0,
        pending: [],
        testable: [{ edgeId: 'e-1', name: 'edge-a' }],
      },
    ],
    sameCoverSite: [],
    ...o,
  };
}

const kind = (s: NamesStep) => s.kind;

describe('the next step', () => {
  test('follows the way to members, one step at a time', () => {
    expect(kind(namesStep(transport(), { ...on, names: false }, NODE))).toBe('names_off');
    expect(kind(namesStep(transport({ list: null }), on, NODE))).toBe('manage');
    const off = transport();
    off.list!.enabled = false;
    expect(kind(namesStep(off, on, NODE))).toBe('list_off');
    expect(
      kind(
        namesStep(
          transport(
            { send: { rolloutId: 'r', generation: 3, phase: 'writing', witness: null } },
            { toSend: 2 },
          ),
          on,
          NODE,
        ),
      ),
    ).toBe('sending');
    expect(kind(namesStep(transport({}, { toSend: 2 }), on, NODE))).toBe('send');
    expect(
      kind(
        namesStep(
          transport(
            { send: { rolloutId: 'r', generation: 3, phase: 'failed', witness: null } },
            { toSend: 2 },
          ),
          on,
          NODE,
        ),
      ),
    ).toBe('send_again');
    const suggested = transport();
    suggested.list!.suggestions = 11;
    expect(namesStep(suggested, on, NODE)).toEqual({ kind: 'add_suggestions', count: 11 });
    expect(namesStep(transport({}, { checking: 3 }), on, NODE)).toEqual({
      kind: 'checking',
      count: 3,
    });
    expect(kind(namesStep(transport(), on, NODE))).toBe('done');
  });

  test('a send comes before a test: one test afterwards proves all of it', () => {
    const t = transport({}, { toSend: 1, waitingTest: 2 });
    t.nodes[0]!.waitingTest = 2;
    expect(kind(namesStep(t, on, NODE))).toBe('send');
  });

  test('a test is offered on the node that lacks the names, through a proven address', () => {
    const t = transport({}, { waitingTest: 2 });
    t.nodes[0]!.waitingTest = 2;
    expect(kind(namesStep(t, on, NODE))).toBe('test');
    // Another node's page: nothing to test there.
    expect(kind(namesStep(t, on, 'n-2'))).toBe('done');
    // A name list's page (every node at once): the test is per node, below.
    expect(namesStep(t, on, null)).toEqual({ kind: 'test_nodes', nodes: 1 });
    t.nodes[0]!.testable = [];
    expect(kind(namesStep(t, on, NODE))).toBe('test_needs_address');
  });

  test('a send held back by a switch says which one', () => {
    expect(namesStep(transport({}, { toSend: 1 }), { ...on, backendChanges: false }, NODE)).toEqual(
      { kind: 'send_blocked', why: 'backend_changes_off' },
    );
    expect(namesStep(transport({}, { toSend: 1 }), { ...on, backendSetUp: false }, NODE)).toEqual({
      kind: 'send_blocked',
      why: 'not_set_up',
    });
  });

  test('every step has words, and only steps that act have a button', () => {
    const t = transport();
    const steps: NamesStep[] = [
      { kind: 'names_off' },
      { kind: 'manage' },
      { kind: 'list_off' },
      { kind: 'sending' },
      { kind: 'send' },
      { kind: 'send_again' },
      { kind: 'send_blocked', why: 'backend_changes_off' },
      { kind: 'send_blocked', why: 'not_set_up' },
      { kind: 'test', node: t.nodes[0]! },
      { kind: 'test_needs_address', node: t.nodes[0]! },
      { kind: 'test_nodes', nodes: 2 },
      { kind: 'add_suggestions', count: 2 },
      { kind: 'checking', count: 2 },
      { kind: 'done' },
    ];
    for (const s of steps) {
      const w = stepWords(s, t);
      expect(w.length).toBeGreaterThan(10);
      expect(w).not.toMatch(/—|edge\.sni|q_|family|target|transport/i);
    }
    expect(Object.keys(STEP_BUTTON).sort()).toEqual(
      ['add_suggestions', 'manage', 'send', 'send_again', 'test'].sort(),
    );
  });
});

describe('the status line', () => {
  test("counts this node's members, then what waits", () => {
    const t = transport({}, { checking: 2, failing: 1 });
    t.list!.suggestions = 11;
    t.nodes[0]!.inUse = 3;
    expect(namesStatus(t, NODE)).toEqual({
      dot: 'amber',
      text: '3 names in use · 2 being checked · 1 failing · 11 suggestions',
    });
    expect(namesStatus(transport(), NODE)).toEqual({ dot: 'green', text: '4 names in use' });
    expect(namesStatus(transport({ list: null }), NODE).text).toBe('4 names set by hand');
    expect(namesStatus(transport({ list: null, listed: 1 }), NODE).text).toBe('1 name set by hand');
  });
});

describe('a suggestion in one line', () => {
  const base: SniCandidateRow = {
    id: 'c',
    name: 'img.site.example',
    site: 'site.example',
    sources: ['cert'],
    rank: 1234,
    state: 'new',
    inFamily: null,
    check: {
      at: '2026-10-27T00:00:00.000Z',
      code: null,
      tlsVersion: 'TLSv1.3',
      alpn: 'h2',
      answers: { v4: 1, v6: 0, onNetwork: 'all' },
      shown: ['192.0.2.1'],
      dialled: '192.0.2.1',
      port: 443,
    },
    extra: null,
    passes: 1,
    baseScore: 20,
    score: 40,
    parts: null,
    listed: true,
    timing: null,
    own: null,
    ooni: null,
    countries: [],
    firstSeenAt: '2026-10-27T00:00:00.000Z',
  };
  test('what is known, never the score', () => {
    expect(suggestionReason(base)).toBe("A popular site, on the cover site's certificate.");
    expect(
      suggestionReason({
        ...base,
        rank: null,
        sources: ['pasted'],
        timing: {
          at: base.firstSeenAt,
          place: 'US/Example City',
          endpoint: '192.0.2.1',
          port: 443,
          connectMs: 13,
          tlsMs: null,
          probes: 2,
        },
        countries: [
          { cc: 'IR', at: base.firstSeenAt, reading: 'ok', vantages: 2, networks: 2, singled: 0 },
        ],
      }),
    ).toBe('13 ms from the node, works in IR.');
    expect(suggestionReason({ ...base, rank: null, sources: ['pasted'] })).toBe(
      'The cover site serves it.',
    );
  });
});

describe('Needs you', () => {
  test('a send held back, a test to make, suggestions, and names the cover site dropped', () => {
    const t = transport({}, { toSend: 2, failing: 1 });
    t.list!.suggestions = 5;
    const view: SniTransportsView = {
      switches: { ...on, backendChanges: false },
      transports: [t, transport({ transportUuid: 't-2', list: null })],
    };
    expect(namesNeedsYou(view).map((r) => r.text)).toEqual([
      'VLESS_REALITY: 2 checked names cannot reach the nodes: changes to the backend are off.',
      'VLESS_REALITY: 5 suggested names to add.',
      'VLESS_REALITY: 1 name no longer served by the cover site.',
    ]);
    const waiting = transport({}, { waitingTest: 1 });
    waiting.nodes[0]!.waitingTest = 1;
    expect(namesNeedsYou({ switches: on, transports: [waiting] })).toEqual([
      {
        key: 'names-test:t-1:node-one',
        text: 'VLESS_REALITY on node-one: 1 name waits for a test.',
        nodeUuid: NODE,
      },
    ]);
    expect(namesNeedsYou({ switches: { ...on, names: false }, transports: [t] })).toEqual([]);
  });
});

describe('what each action did, in words', () => {
  const lines = (n: number, verdict: 'added' | 'in_other_family') =>
    Array.from({ length: n }, (_, i) => ({
      input: `n${i}.example`,
      name: `n${i}.example`,
      verdict,
    }));
  test('managing, adding, sending, testing and looking for more', () => {
    expect(
      managedWords({
        dryRun: false,
        family: 'f',
        created: true,
        bindingId: 'b',
        imported: { added: 2, lines: [...lines(2, 'added'), ...lines(1, 'in_other_family')] },
        placeSet: false,
        cert: {
          ok: true,
          listed: 6,
          added: 4,
          known: 0,
          ignored: 0,
          inFamily: 2,
          invalid: 0,
          capped: 0,
        },
      }),
    ).toBe(
      "FCP manages these names now: 2 names taken in, each checked against the cover site first. Left out: 1 in another list. The cover site's certificate lists 6 names: new ones show up as suggestions once checked.",
    );
    // Taking an existing list back: its names are already in it, never "left out".
    expect(
      managedWords({
        dryRun: false,
        family: 'f',
        created: false,
        bindingId: 'b',
        imported: {
          added: 0,
          lines: lines(9, 'added').map((l) => ({ ...l, verdict: 'duplicate' as const })),
        },
        placeSet: false,
        cert: null,
      }),
    ).toBe('FCP manages these names now. 9 names were already in the list.');
    expect(addedWords({ added: 3, lines: lines(3, 'added') })).toBe(
      '3 names added. Each is checked against the cover site, then goes to the node with the next send.',
    );
    // Each reason a line was left out, with its count: a typo is never "already listed".
    expect(
      addedWords({
        added: 0,
        lines: [
          { input: 'not a name', name: null, verdict: 'invalid' },
          { input: 'a.example', name: 'a.example', verdict: 'duplicate' },
        ],
      }),
    ).toBe(
      '0 names added. Each is checked against the cover site, then goes to the node with the next send. Left out: 1 already listed, 1 not a host name.',
    );
    const plan = {
      backendServerId: 's',
      profileUuid: 'p',
      inboundTag: 'VLESS_REALITY',
      generation: 2,
      names: ['a.example', 'b.example'],
      added: ['b.example'],
      removed: [],
      witness: 'b.example',
      overflow: 0,
      changed: true,
    };
    const two = transport({
      profileNodes: [
        { nodeUuid: 'a', name: 'a' },
        { nodeUuid: 'b', name: 'b' },
      ],
    });
    expect(sendPlanWords(plan, two)).toEqual([
      '1 name will be added.',
      'Every node on the profile Main (2 nodes) restarts Xray once. People connected there reconnect within a few seconds.',
      'Members get the new names once a test on the node proves it accepts them. One test proves all of them.',
    ]);
    expect(sendPlanWords({ ...plan, changed: false }, two)).toEqual([
      'The backend already lists exactly these names. Nothing to send.',
    ]);
    expect(provenWords(6, 'node-one')).toBe('6 names are now given to members on node-one.');
    expect(provenWords(0, 'node-one')).toBe('Recorded. node-one had nothing new to hand out.');
    expect(
      lookedWords(
        { ok: true, listed: 6, added: 1, known: 5, ignored: 0, inFamily: 0, invalid: 0, capped: 0 },
        { queued: 1 },
      ),
    ).toBe(
      "The cover site's certificate lists 6 names, 1 new. Certificate logs are being read too. New names show up as suggestions once checked.",
    );
  });
});

describe('which name a test presents', () => {
  test("the send's witness while it waits there, else a name still waiting there", () => {
    expect(
      testNameChoice({ witness: 'w.example' }, { pending: ['a.example', 'w.example'] }),
    ).toEqual({
      kind: 'witness',
    });
    // Proven already (no longer waiting), or no witness: one of the names still waiting.
    expect(testNameChoice({ witness: 'w.example' }, { pending: ['a.example'] })).toEqual({
      kind: 'pick',
      names: ['a.example'],
    });
    expect(testNameChoice({ witness: null }, { pending: ['a.example', 'b.example'] })).toEqual({
      kind: 'pick',
      names: ['a.example', 'b.example'],
    });
  });
});

describe('a node on the list page', () => {
  test('what its members get, and a test it waits for', () => {
    const n = transport().nodes[0]!;
    expect(nodeLineWords(n)).toEqual({ dot: 'green', text: '4 names in use' });
    expect(nodeLineWords({ ...n, waitingTest: 2 })).toEqual({
      dot: 'amber',
      text: '4 names in use · 2 waiting for a test',
    });
    expect(nodeLineWords({ ...n, waitingTest: 1, testable: [] }).text).toBe(
      '4 names in use · 1 waiting for a test: try one of its addresses first',
    );
  });
});
