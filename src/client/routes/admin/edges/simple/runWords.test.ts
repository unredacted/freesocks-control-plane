import { describe, expect, it } from 'vitest';
import { SETUP_RUN_NEEDS } from '../../../../../shared/contracts/edgeCodes';
import {
  automationOn,
  hideButton,
  moreDirectWords,
  needButtons,
  planWords,
  runTestItems,
  runTestLines,
} from './runWords';

describe('needButtons', () => {
  it('gives every need one button, at most one secondary, no em-dash', () => {
    for (const code of SETUP_RUN_NEEDS) {
      const b = needButtons(code);
      expect(b.primary.label.trim()).toBeTruthy();
      for (const s of [b.primary.label, b.secondary?.label ?? '', b.hint ?? '']) {
        expect(s).not.toContain('—');
        expect(s).not.toContain('/api/');
      }
    }
    expect(needButtons('try_it')).toMatchObject({
      primary: { action: 'continue' },
      secondary: { action: 'retry_another_address' },
    });
    expect(needButtons('address_unreachable').secondary?.action).toBe('accept_partial');
    expect(needButtons('hide_failed').hint).toMatch(/backend yourself/);
    expect(needButtons('whatever').primary.action).toBe('retry');
    // Approving go-live is the one way on: no retry that would only park the run again.
    const approve = needButtons('node_not_approved');
    expect(approve.primary).toEqual({ label: 'Approve go-live', action: 'approve' });
    expect(approve.secondary).toBeUndefined();
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
