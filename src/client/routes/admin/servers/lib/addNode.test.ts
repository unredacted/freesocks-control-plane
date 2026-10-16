import { describe, expect, test } from 'vitest';
import { nodeFormProblems, placementCheck, placementLines, type NodeForm } from './addNode';

const form = (over: Partial<NodeForm> = {}): NodeForm => ({
  name: 'node-c',
  address: '192.0.2.40',
  port: '',
  countryCode: '',
  profileUuid: 'p1',
  transportUuids: ['t1'],
  ...over,
});

describe('nodeFormProblems', () => {
  test('a complete form has none', () => {
    expect(nodeFormProblems(form())).toEqual([]);
    expect(nodeFormProblems(form({ port: '2222', countryCode: 'de' }))).toEqual([]);
  });
  test('each field says what it needs, in words', () => {
    expect(nodeFormProblems(form({ name: ' ' }))).toEqual(['Give the node a name.']);
    // The server's rule: 3 to 30 plain characters.
    expect(nodeFormProblems(form({ name: 'bad/name' }))[0]).toMatch(/3 to 30 letters/);
    expect(nodeFormProblems(form({ name: 'ab' }))[0]).toMatch(/3 to 30 letters/);
    expect(nodeFormProblems(form({ name: 'n'.repeat(31) }))[0]).toMatch(/3 to 30 letters/);
    expect(nodeFormProblems(form({ name: 'n'.repeat(30) }))).toEqual([]);
    expect(nodeFormProblems(form({ name: 'node c.1_x' }))).toEqual([]);
    expect(nodeFormProblems(form({ name: 'Node-C' }), ['node-c'])).toEqual([
      'Another node already has this name.',
    ]);
    expect(nodeFormProblems(form({ address: '' }))).toEqual([
      'Say where the backend reaches the node.',
    ]);
    expect(nodeFormProblems(form({ port: '70000' }))).toEqual([
      'The port is a whole number from 1 to 65535.',
    ]);
    expect(nodeFormProblems(form({ countryCode: 'DEU' }))).toEqual([
      'The country code is two letters.',
    ]);
    expect(nodeFormProblems(form({ profileUuid: '' }))).toEqual(['Pick the profile it runs.']);
    expect(nodeFormProblems(form({ transportUuids: [] }))).toEqual([
      'Pick at least one transport it serves.',
    ]);
  });
});

describe('placementCheck', () => {
  const groups = [
    {
      groupUuid: 'g1',
      name: 'reality-b',
      membersCount: 3,
      transportTags: ['r'],
      transportUuids: ['t1'],
    },
    {
      groupUuid: 'g2',
      name: 'reality-a',
      membersCount: 0,
      transportTags: ['r'],
      transportUuids: ['t1'],
    },
    { groupUuid: 'g3', name: 'ws', membersCount: 0, transportTags: [], transportUuids: [] },
  ];
  const pools = {
    observedAt: null,
    modes: [
      { modeSlug: 'freedom-reality', modeGroups: 2, unknownHere: 0, withoutTransports: [] },
      { modeSlug: 'freedom-ws', modeGroups: 2, unknownHere: 1, withoutTransports: ['ws'] },
      { modeSlug: 'privacy', modeGroups: 0, unknownHere: 0, withoutTransports: [] },
    ],
  };

  test('per transport, the mode groups that list it; per pool, what the backend says', () => {
    const c = placementCheck(
      [
        { transportUuid: 't1', tag: 'reality-in' },
        { transportUuid: 't2', tag: 'ws-in' },
      ],
      groups,
      pools,
    );
    expect(c.transports).toEqual([
      { transportUuid: 't1', tag: 'reality-in', groups: ['reality-a', 'reality-b'] },
      { transportUuid: 't2', tag: 'ws-in', groups: [] },
    ]);
    const lines = placementLines(c);
    expect(lines).toEqual([
      { ok: true, text: 'reality-in is in the mode groups reality-a and reality-b.' },
      {
        ok: false,
        text: 'ws-in is in no mode group, so no member can reach it through this node yet.',
      },
      { ok: true, text: 'The freedom-reality pool has 2 mode groups.' },
      {
        ok: false,
        text: 'The freedom-ws pool names 1 mode group this backend does not have (it may be on another backend).',
      },
      { ok: false, text: 'In the freedom-ws pool, ws lists no transport.' },
      { ok: false, text: 'The privacy pool is empty: that mode issues no keys here.' },
    ]);
    for (const l of lines) expect(l.text).not.toMatch(/—/);
  });

  test('without the pool check yet, only the transports', () => {
    expect(placementCheck([{ transportUuid: 't1', tag: 'r' }], groups, null).pools).toEqual([]);
  });
});
