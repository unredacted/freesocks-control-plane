import { describe, expect, it } from 'vitest';
import { SETUP_RUN_NEEDS } from '../../../../../shared/contracts/edgeCodes';
import {
  automationNote,
  automationOn,
  automationState,
  hideButton,
  moreDirectWords,
  needButtons,
  nodeAutomationWords,
  spareInUseWords,
  planWords,
  replaceWords,
  setWords,
  providerPickWords,
  runTestItems,
  runTestLines,
  TEST_PROFILE_NOTE,
} from './runWords';

describe('needButtons', () => {
  it('gives every need one button, at most one secondary, no em-dash', () => {
    for (const code of SETUP_RUN_NEEDS) {
      const b = needButtons(code);
      expect(b.primary.label.trim()).toBeTruthy();
      for (const s of [
        b.primary.label,
        b.secondary?.label ?? '',
        b.more?.label ?? '',
        b.hint ?? '',
      ]) {
        expect(s).not.toContain('—');
        expect(s).not.toContain('/api/');
      }
    }
    expect(needButtons('try_it')).toMatchObject({
      primary: { action: 'continue' },
      secondary: { action: 'retry_another_address' },
    });
    // The outside check's two cards also check the same address afresh.
    expect(needButtons('address_unreachable')).toMatchObject({
      primary: { label: 'Check again', action: 'check_again' },
      secondary: { action: 'retry_another_address' },
      more: { label: 'Go live anyway', action: 'accept_partial' },
    });
    expect(needButtons('blocked_in')).toMatchObject({
      primary: { action: 'retry_another_address' },
      more: { label: 'Check again', action: 'check_again' },
    });
    // Every other card keeps one button and at most one secondary.
    for (const code of SETUP_RUN_NEEDS)
      if (code !== 'address_unreachable' && code !== 'blocked_in')
        expect(needButtons(code).more).toBeUndefined();
    expect(needButtons('hide_failed').hint).toMatch(/backend yourself/);
    // FCP resets the test account on every try: "Try again" re-enters the card.
    expect(needButtons('test_account_used_up')).toEqual({
      primary: { label: 'Try again', action: 'retry' },
    });
    expect(needButtons('whatever').primary.action).toBe('retry');
    // Approving go-live is the one way on: no retry that would only park the run again.
    const approve = needButtons('node_not_approved');
    expect(approve.primary).toEqual({ label: 'Approve go-live', action: 'approve' });
    expect(approve.secondary).toBeUndefined();
  });
});

describe('TEST_PROFILE_NOTE', () => {
  it('says the profile is for a short test and is removed after, in plain words', () => {
    expect(TEST_PROFILE_NOTE).toMatch(/short test only/);
    expect(TEST_PROFILE_NOTE).toMatch(/Remove this profile from the client/);
    expect(TEST_PROFILE_NOTE).not.toContain('—');
    expect(TEST_PROFILE_NOTE).not.toContain('/api/');
  });
});

describe('replaceWords', () => {
  it('names the address and its transport, and says it is removed and replaced for good', () => {
    const w = replaceWords({ name: 'REALITY in Region B', endpoint: '198.51.100.80:443' });
    expect(w.title).toBe('Replace 198.51.100.80:443?');
    expect(w.body).toContain('REALITY in Region B at 198.51.100.80:443 is removed');
    expect(w.body).toContain('a new address is created in its place');
    expect(w.body).toContain('cannot be brought back');
    expect(w.body).toContain('nothing is removed');
    expect(replaceWords({ name: null, endpoint: '198.51.100.80:443' }).body).toMatch(
      /^198\.51\.100\.80:443 is removed/,
    );
    for (const s of [w.title, w.body]) expect(s).not.toContain('—');
  });
});

describe('automationOn', () => {
  it('needs all four switches', () => {
    const on = {
      enabled: true,
      autoRotate: true,
      autoProvisionToDesired: true,
      probe: { enabled: true },
    };
    expect(automationOn(on)).toBe(true);
    expect(automationOn({ ...on, probe: { enabled: false } })).toBe(false);
    expect(automationOn({ ...on, autoRotate: false })).toBe(false);
  });
});

describe('automation state and words', () => {
  const on = {
    enabled: true,
    autoRotate: true,
    autoProvisionToDesired: true,
    probe: { enabled: true },
  };
  // The walk's set-up (docs/beta-deploy.md "Walking automatic rotation"): spares by hand.
  const walk = { ...on, autoProvisionToDesired: false };
  const node = { autoRotate: true, setupOwned: false };
  const noEmDash = (s: string | null) => expect(s ?? '').not.toContain('—');

  it('replacement is the master switch and automatic rotation, not spares or probes', () => {
    expect(automationState(on)).toEqual({ replaces: true, makesSpares: true, probes: true });
    expect(automationState(walk)).toEqual({ replaces: true, makesSpares: false, probes: true });
    expect(automationState({ ...on, enabled: false })).toEqual({
      replaces: false,
      makesSpares: false,
      probes: true,
    });
    expect(automationState({ ...on, autoRotate: false }).replaces).toBe(false);
  });

  it('the Edges home says what is left to the operator under an ON switch', () => {
    expect(automationNote(automationState(on))).toBeNull();
    expect(automationNote(automationState({ ...on, enabled: false }))).toBeNull();
    expect(automationNote(automationState(walk))).toMatch(/does not make new spares/);
    expect(automationNote(automationState({ ...on, probe: { enabled: false } }))).toMatch(
      /probes are off/,
    );
    const both = automationNote(automationState({ ...walk, probe: { enabled: false } }));
    expect(both).toMatch(/spares/);
    expect(both).toMatch(/probes/);
    for (const c of [walk, { ...on, probe: { enabled: false } }])
      noEmDash(automationNote(automationState(c)));
  });

  it('the node card never calls automation off while the master switch is on', () => {
    // The beta walk: everything on except new spares. Not "off".
    const w = nodeAutomationWords(walk, node);
    expect(w.line).toMatch(/switches members to a tested spare on its own/);
    expect(w.line).not.toMatch(/off/i);
    expect(w.spares).toMatch(/does not make new spares on its own/);
    expect(nodeAutomationWords(on, node)).toEqual({
      line: 'When an address looks blocked, FCP switches members to a tested spare on its own.',
      spares: null,
    });
  });

  it('names the gate that actually holds this node', () => {
    expect(nodeAutomationWords({ ...on, enabled: false }, node).line).toMatch(
      /Edge automation is off for every node/,
    );
    expect(nodeAutomationWords({ ...on, autoRotate: false }, node).line).toMatch(
      /Automatic rotation is off for every node/,
    );
    expect(nodeAutomationWords(on, { ...node, setupOwned: true }).line).toMatch(/setup run/);
    // A cancelled or failed setup left it owned, but no run works on it.
    expect(nodeAutomationWords(on, { ...node, setupOwned: true, runLive: false }).line).toMatch(
      /not live yet/,
    );
    expect(nodeAutomationWords(on, { ...node, autoRotate: false }).line).toMatch(
      /Off for this node/,
    );
    // Spares only matter where replacement can act.
    expect(nodeAutomationWords({ ...walk, enabled: false }, node).spares).toBeNull();
    expect(nodeAutomationWords(walk, { ...node, autoRotate: false }).spares).toBeNull();
    for (const c of [on, walk, { ...on, enabled: false }, { ...on, autoRotate: false }])
      for (const n of [node, { ...node, autoRotate: false }, { ...node, setupOwned: true }]) {
        const w = nodeAutomationWords(c, n);
        noEmDash(w.line);
        noEmDash(w.spares);
      }
  });
});

describe('runTestItems', () => {
  it('copies the binding exactly', () => {
    const items = runTestItems({
      testLinks: [
        {
          edgeId: 'e1',
          listenerKey: 'main',
          link: 'vless://x',
          format: 'links',
          method: 'test_link',
          binding: {
            endpoint: '192.0.2.4:443',
            listenerRevision: 3,
            configHash: 'h',
            issuedAt: 'x',
          },
        },
      ],
    });
    expect(items).toEqual([
      {
        edgeId: 'e1',
        listenerKey: 'main',
        name: null,
        link: 'vless://x',
        method: 'test_link',
        endpoint: '192.0.2.4:443',
        listenerRevision: 3,
        configHash: 'h',
      },
    ]);
  });
});

describe('runTestLines', () => {
  const link = (edgeId: string, listenerKey: string, issuedAt: string) => ({
    edgeId,
    listenerKey,
    link: `vless://${edgeId}`,
    format: 'links',
    method: 'test_link' as const,
    binding: { endpoint: `${edgeId}:443`, listenerRevision: 1, configHash: 'h', issuedAt },
  });
  const listener = (listenerKey: string, edgeId: string | null) => ({
    listenerKey,
    locationId: null,
    layer: 'l4' as const,
    edgeId,
    verify: 'pending' as const,
    published: false,
    transport:
      listenerKey === 'a'
        ? {
            protocol: 'vless' as const,
            streamTransport: 'raw' as const,
            security: 'reality' as const,
            originPort: 443,
          }
        : null,
  });
  it('keeps a ticked line on the card as done, in listener order, and drops a replaced edge', () => {
    const { items, done } = runTestLines({
      listeners: [listener('a', 'e1'), listener('b', 'e2'), listener('c', 'e3')],
      // e1 was ticked after its link (saved, card not rebuilt yet); e2 is pending;
      // e3 was ticked and its card line is gone; e0 is an edge the run replaced.
      testLinks: [
        link('e2', 'b', '2026-10-16T10:00:00.000Z'),
        link('e1', 'a', '2026-10-16T10:00:00.000Z'),
      ],
      testedEndpoints: [
        { edgeId: 'e1', listenerKey: 'a', endpoint: 'e1:443', at: '2026-10-16T10:01:00.000Z' },
        { edgeId: 'e3', listenerKey: 'c', endpoint: 'e3:443', at: '2026-10-16T09:00:00.000Z' },
        { edgeId: 'e0', listenerKey: 'b', endpoint: 'e0:443', at: '2026-10-16T09:00:00.000Z' },
      ],
    });
    expect(items.map((i) => i.edgeId)).toEqual(['e1', 'e2', 'e3']);
    expect([...done].sort()).toEqual(['e1', 'e3']);
    // Lines are named by what they carry, never by the listener key.
    expect(items.map((i) => i.name)).toEqual(['VLESS · raw · REALITY, port 443', null, null]);
  });
  it('a link issued after the tick is a retest: pending again', () => {
    const { done } = runTestLines({
      listeners: [listener('a', 'e1')],
      testLinks: [link('e1', 'a', '2026-10-16T11:00:00.000Z')],
      testedEndpoints: [
        { edgeId: 'e1', listenerKey: 'a', endpoint: 'e1:443', at: '2026-10-16T10:00:00.000Z' },
      ],
    });
    expect(done.size).toBe(0);
  });
});

describe('planWords', () => {
  const inbound = (over: Record<string, unknown>) => ({
    listenerKey: 'main',
    sourceTag: 'main',
    listenerSpec: null,
    layers: ['l4' as const],
    frontable: true,
    formats: { links: true, singbox: true, clash: true },
    needsName: false,
    ...over,
  });
  it('words the review, the consent and the formats', () => {
    const w = planWords(
      {
        nodeName: 'node-a',
        inbounds: [
          inbound({}),
          inbound({ listenerKey: 'ws', formats: { links: true, singbox: false, clash: true } }),
        ],
        requiredListeners: ['main', 'ws'],
        directHosts: [
          { uuid: 'u1', remark: 'A', inboundUuid: 'i', covered: true },
          { uuid: 'u2', remark: 'B', inboundUuid: 'j', covered: false },
        ],
        renderGlobal: { willEnable: true, affectedRelays: ['node-b'] },
      },
      'Main account',
    );
    expect(w.sentence).toBe(
      'FCP creates 2 addresses in Main account, checks each one from outside and with you, then moves node-a behind them.',
    );
    expect(w.uncovered).toMatchObject({ count: 1, uuids: ['u2'], remarks: ['B'] });
    expect(w.button).toBe('Protect and hide 1 direct address');
    expect(w.uncovered?.statement).toMatch(/^1 direct address on the backend uses/);
    expect(hideButton(2)).toBe('Protect and hide 2 direct addresses');
    expect(moreDirectWords(1)).toMatch(/^One more direct address on the backend uses/);
    expect(moreDirectWords(3)).toMatch(/^3 more direct addresses on the backend use/);
    expect(w.renderGlobal).toMatch(/1 other node/);
    expect(w.formats).toBe(
      'Works for link and Clash subscriptions; other formats keep the direct address.',
    );
  });
  it('judges the formats by the protected transports only (a choice on a busy node)', () => {
    const w = planWords(
      {
        nodeName: 'n',
        inbounds: [
          inbound({}),
          inbound({
            listenerKey: 'other',
            sourceTag: 'other',
            formats: { links: true, singbox: false, clash: false },
          }),
        ],
        requiredListeners: ['main'],
        directHosts: [],
        renderGlobal: { willEnable: false, affectedRelays: [] },
      },
      'Acc',
    );
    expect(w.formats).toBe('Works for every subscription format.');
  });
  it('is quiet when nothing needs consent', () => {
    const w = planWords(
      {
        nodeName: 'n',
        inbounds: [inbound({})],
        requiredListeners: ['main'],
        directHosts: [],
        renderGlobal: { willEnable: false, affectedRelays: [] },
      },
      'Acc',
    );
    expect(w.uncovered).toBeNull();
    expect(w.renderGlobal).toBeNull();
    expect(w.button).toBe('Protect this node');
    expect(w.formats).toBe('Works for every subscription format.');
  });
});

describe('setWords', () => {
  const set = {
    picks: [
      { locationId: 'x', accountId: 'a', label: 'Region A' },
      { locationId: 'y', accountId: 'b', label: 'Region B' },
    ],
    targets: [
      { listenerKey: 'main', locationId: 'x' },
      { listenerKey: 'main', locationId: 'y' },
      { listenerKey: 'ws', locationId: 'x' },
    ],
    reduced: [{ listenerKey: 'ws' }],
    uncovered: [],
    tooLarge: false,
  };
  const name = (k: string) => (k === 'main' ? 'REALITY' : 'WebSocket');
  const acct = (id: string) => (id === 'a' ? 'Acct A' : 'Acct B');

  it('says how many addresses each pick gets and which transports have no backup elsewhere', () => {
    const w = setWords(set, name, acct);
    expect(w.lines.map((l) => l.text)).toEqual([
      '2 addresses in Region A (Acct A).',
      '1 address in Region B (Acct B).',
    ]);
    expect(w.reduced).toBe('Members on WebSocket have no backup at another provider.');
    expect(w.uncovered).toBeNull();
    expect(w.where).toBe('2 locations');
    for (const t of [...w.lines.map((l) => l.text), w.reduced]) expect(t).not.toContain('—');
  });

  it('names a transport no pick carries, and one pick by its account and place', () => {
    const w = setWords({ ...set, picks: [set.picks[1]!], uncovered: ['ws'] }, name, acct);
    expect(w.uncovered).toBe('No picked location carries WebSocket. Add one that can.');
    expect(w.where).toBe('Acct B (Region B)');
  });
});

describe('planWords: the fleet-wide sentence', () => {
  it('says no "0 other nodes" when going live turns rendering on for this node only', () => {
    const w = planWords(
      {
        nodeName: 'node-a',
        inbounds: [],
        requiredListeners: ['a'],
        directHosts: [],
        renderGlobal: { willEnable: true, affectedRelays: [] },
      },
      'Acct',
      2,
    );
    expect(w.renderGlobal).toBe('Going live also turns on protected delivery.');
    expect(w.sentence).toMatch(/^FCP creates 2 addresses in Acct/);
  });
});

describe('providerPickWords', () => {
  it('counts per location, a cooling line, and what members miss', () => {
    const now = Date.parse('2026-10-18T12:00:00Z');
    const w = providerPickWords(
      {
        hasSet: true,
        picks: [
          {
            locationId: 'x',
            accountId: 'a',
            accountName: 'Acct A',
            provider: 'acme',
            label: 'Region A',
            usable: true,
            qualified: true,
            inUse: 2,
            spare: 1,
            coolingUntil: '2026-10-18T12:30:00Z',
            addedAt: '2026-10-01T00:00:00Z',
            options: null,
          },
        ],
        reduced: [{ listenerKey: 'main', reason: 'one_group' }],
        coolingOnly: [],
        uncarried: [],
        deficit: 1,
      },
      (k) => (k === 'main' ? 'REALITY' : k),
      now,
    );
    expect(w.picks[0]).toEqual({
      locationId: 'x',
      counts: '2 in use, 1 spare.',
      cooling: 'An address here was just blocked: automatic work keeps away for about 30 minutes.',
    });
    expect(w.notes).toEqual([
      'Members on REALITY have no backup at another provider.',
      '1 address is still missing; automatic upkeep adds it.',
    ]);
    expect(w.outside).toEqual([]);
  });

  it("names a location outside the node's set, and why a failed run's spare is there", () => {
    const w = providerPickWords({
      hasSet: true,
      picks: [],
      outside: [
        {
          locationId: 'y',
          accountId: 'b',
          accountName: 'Acct B',
          provider: 'globex',
          label: 'Region B',
          qualified: false,
          inUse: 0,
          spare: 1,
        },
      ],
      reduced: [],
      coolingOnly: [],
      uncarried: [],
      deficit: 0,
    });
    expect(w.outside).toEqual([
      {
        locationId: 'y',
        counts: '0 in use, 1 spare.',
        why: expect.stringMatching(/a run that did not go live.*change only when a run goes live/),
      },
    ]);
  });
});

describe('spareInUseWords', () => {
  const on = { enabled: true, autoPublishStandby: true };
  const node = {
    enabled: true,
    setupOwned: false,
    desiredPublished: 2,
    publishedEdgeIds: ['e1', null],
  };
  it('a node that wants more addresses in use takes a kept or added spare at once', () => {
    expect(spareInUseWords(on, node)).toBe(
      'It may be put in use at once: this node wants 2 addresses in use and has 1.',
    );
    expect(spareInUseWords(on, { ...node, desiredPublished: 1, publishedEdgeIds: [] })).toBe(
      'It may be put in use at once: this node wants 1 address in use and has 0.',
    );
  });
  it('it stays a spare when the pool is full or nothing publishes on its own', () => {
    expect(spareInUseWords(on, { ...node, publishedEdgeIds: ['e1', 'e2'] })).toBeNull();
    expect(spareInUseWords({ ...on, autoPublishStandby: false }, node)).toBeNull();
    expect(spareInUseWords({ ...on, enabled: false }, node)).toBeNull();
    expect(spareInUseWords(on, { ...node, setupOwned: true })).toBeNull();
    expect(spareInUseWords(on, { ...node, enabled: false })).toBeNull();
  });
});
