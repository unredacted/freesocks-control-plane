import { describe, expect, it } from 'vitest';
import { SETUP_RUN_NEEDS } from '../../../../../shared/contracts/edgeCodes';
import { automationOn, needButtons, planWords, runTestItems } from './runWords';

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
    expect(needButtons('hide_failed').hint).toMatch(/panel yourself/);
    expect(needButtons('whatever').primary.action).toBe('retry');
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
          binding: { endpoint: '1.2.3.4:443', listenerRevision: 3, configHash: 'h', issuedAt: 'x' },
        },
      ],
    });
    expect(items).toEqual([
      {
        edgeId: 'e1',
        listenerKey: 'main',
        link: 'vless://x',
        method: 'test_link',
        endpoint: '1.2.3.4:443',
        listenerRevision: 3,
        configHash: 'h',
      },
    ]);
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
    expect(w.button).toBe('Protect and hide 1 unsupported host');
    expect(w.renderGlobal).toMatch(/1 other node/);
    expect(w.formats).toBe(
      'Works for link and Clash subscriptions; other formats keep the direct address.',
    );
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
