import { describe, expect, it, vi } from 'vitest';
import { ATTENTION_ACTIONS } from '../../../../../shared/contracts/edgeCodes';
import { plainWords } from '../../../../lib/edgeCodes';
import { ATTENTION_ACTION_PLAN, attentionCallable, type AttentionItem } from './attention';
import { runAttentionCall, type AttentionCallApi, type AttentionCallDeps } from './attentionCalls';

const item = (over: Partial<AttentionItem>): AttentionItem => ({
  id: 'x:1',
  kind: 'pool_below_desired',
  severity: 'info',
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

/** The AttentionItem the Nodes home showed: 1 of 2 in use, 1 spare ready, "Put it in use". */
const spareReady = item({
  id: 'pool_below_desired:r1',
  edgeId: 'e-spare',
  facts: { published: 1, desired: 2, standbys: 1 },
  action: 'publish',
});

type Item = (item: AttentionItem) => void;

/** Fake deps: every call and effect a mock; `host` adds the in-place test card and go-live. */
function fakes({ plain = true, host = false } = {}) {
  const api = {
    publish: vi.fn<AttentionCallApi['publish']>(async () => ({ rotationId: 'rot-publish' })),
    rotate: vi.fn<AttentionCallApi['rotate']>(async () => ({ rotationId: 'rot-rotate' })),
    provision: vi.fn<AttentionCallApi['provision']>(async () => ({ rotationId: 'rot-provision' })),
    qualify: vi.fn<AttentionCallApi['qualify']>(async () => ({ ok: true })),
    testCredentials: vi.fn<AttentionCallApi['testCredentials']>(async () => ({ ok: true })),
    thaw: vi.fn<AttentionCallApi['thaw']>(async () => ({})),
    rebalance: vi.fn<AttentionCallApi['rebalance']>(async () => ({})),
  };
  const openTest = vi.fn<Item>();
  const goLive = vi.fn<(item: AttentionItem) => Promise<void>>(async () => {});
  const deps = {
    api,
    plain,
    navigate: vi.fn<(href: string) => void>(),
    openRotation: vi.fn<(item: AttentionItem, rotationId: string) => void>(),
    success: vi.fn<(message: string) => void>(),
    error: vi.fn<(message: string) => void>(),
    failed: vi.fn<(e: unknown) => void>(),
    refresh: { item: vi.fn<Item>(), config: vi.fn<() => void>(), providers: vi.fn<() => void>() },
    ...(host ? { openTest, goLive } : {}),
  } satisfies AttentionCallDeps;
  return { deps, api, openTest, goLive };
}

/** How many edge calls the fakes saw. */
const apiCalls = (api: ReturnType<typeof fakes>['api']) =>
  Object.values(api).reduce((n, f) => n + f.mock.calls.length, 0);

describe('runAttentionCall', () => {
  it('puts the named spare in use and opens its run (the Nodes home bug)', async () => {
    const { deps, api } = fakes();
    await runAttentionCall(spareReady, deps);
    expect(api.publish).toHaveBeenCalledExactlyOnceWith('r1', 'e-spare');
    expect(deps.openRotation).toHaveBeenCalledExactlyOnceWith(spareReady, 'rot-publish');
    expect(deps.refresh.item).toHaveBeenCalledWith(spareReady);
    expect(deps.success).toHaveBeenCalledWith(
      'Putting the address in use. Its progress opens now.',
    );
    expect(deps.navigate).not.toHaveBeenCalled();
  });

  it('never only navigates after a confirm, on either screen', async () => {
    const full = { relayId: 'r1', edgeId: 'e1', accountId: 'acc1' };
    const confirmed = ATTENTION_ACTIONS.filter((a) => {
      const plan = ATTENTION_ACTION_PLAN[a];
      return plan.type === 'call' && plan.confirm !== null;
    });
    expect(confirmed.length).toBeGreaterThan(0);
    for (const plain of [true, false]) {
      for (const action of confirmed) {
        const { deps, api } = fakes({ plain });
        await runAttentionCall(item({ ...full, action }), deps);
        expect({ action, plain, calls: apiCalls(api) }).toEqual({ action, plain, calls: 1 });
        expect(deps.navigate).not.toHaveBeenCalled();
      }
    }
  });

  it('runs every call action the host can run, and navigates the rest', async () => {
    const full = { relayId: 'r1', edgeId: 'e1', accountId: 'acc1' };
    for (const action of ATTENTION_ACTIONS) {
      const { deps, api, openTest, goLive } = fakes({ host: true });
      await runAttentionCall(item({ ...full, action }), deps);
      const ran = apiCalls(api) + openTest.mock.calls.length + goLive.mock.calls.length > 0;
      expect({ action, ran }).toEqual({
        action,
        ran: ATTENTION_ACTION_PLAN[action].type === 'call',
      });
      expect(deps.navigate).toHaveBeenCalledTimes(ran ? 0 : 1);
    }
  });

  it('navigates, without a call, when the item lacks what its call needs', async () => {
    const noEdge = item({ action: 'publish', edgeId: null });
    expect(attentionCallable(noEdge)).toBe(false);
    expect(attentionCallable(spareReady)).toBe(true);
    expect(attentionCallable(item({ action: 'open_relay' }))).toBe(false);
    const { deps, api } = fakes();
    await runAttentionCall(noEdge, deps);
    expect(api.publish).not.toHaveBeenCalled();
    expect(deps.navigate).toHaveBeenCalledExactlyOnceWith('/admin/edges/relays/relay-a?tab=edges');
  });

  it('with no spare to publish, the item says open the node or create one, not publish', async () => {
    const { deps, api } = fakes();
    await runAttentionCall(item({ action: 'provision' }), deps);
    expect(api.provision).toHaveBeenCalledExactlyOnceWith('r1');
    expect(api.publish).not.toHaveBeenCalled();
    expect(deps.openRotation).toHaveBeenCalledWith(expect.anything(), 'rot-provision');
    expect(ATTENTION_ACTION_PLAN.open_relay).toEqual({ type: 'navigate' });
  });

  it('opens the test card and go-live in place, or navigates without them', async () => {
    const test = item({ action: 'verify_endpoint', edgeId: 'e1' });
    const withHost = fakes({ host: true });
    await runAttentionCall(test, withHost.deps);
    expect(withHost.openTest).toHaveBeenCalledExactlyOnceWith(test);
    expect(withHost.deps.navigate).not.toHaveBeenCalled();
    const bare = fakes().deps;
    await runAttentionCall(test, bare);
    expect(bare.navigate).toHaveBeenCalledExactlyOnceWith('/admin/edges/nodes/relay-a?test=e1');
    await runAttentionCall(item({ action: 'require_edges' }), bare);
    expect(bare.navigate).toHaveBeenLastCalledWith('/admin/edges/nodes/relay-a');
  });

  it('toasts a failed unconfirmed call; a confirmed one fails in its dialog', async () => {
    const boom = new Error('boom');
    const { deps, api } = fakes();
    api.qualify.mockRejectedValueOnce(boom);
    await expect(
      runAttentionCall(item({ action: 'qualify_front', edgeId: 'e1' }), deps),
    ).rejects.toBe(boom);
    expect(deps.failed).toHaveBeenCalledExactlyOnceWith(boom);
    api.publish.mockRejectedValueOnce(boom);
    await expect(runAttentionCall(spareReady, deps)).rejects.toBe(boom);
    expect(deps.failed).toHaveBeenCalledTimes(1);
    expect(deps.openRotation).not.toHaveBeenCalled();
  });

  it('words a refused check', async () => {
    const { deps, api } = fakes({ plain: false });
    api.qualify.mockResolvedValueOnce({ ok: false });
    await runAttentionCall(item({ action: 'qualify_front', edgeId: 'e1' }), deps);
    expect(deps.error).toHaveBeenCalledWith('The front did not qualify.');
  });
});

describe('confirm copy in both vocabularies', () => {
  const copies = ATTENTION_ACTIONS.flatMap((a) => {
    const plan = ATTENTION_ACTION_PLAN[a];
    return plan.type === 'call' && plan.confirm ? [plan.confirm] : [];
  });

  it('reads the publish confirm in plain words', () => {
    const { title, body } = ATTENTION_ACTION_PLAN.publish.confirm;
    expect(plainWords(title)).toBe('Put this address in use?');
    expect(plainWords(body)).toBe(
      'Members of this protected node start receiving this address on their next subscription refresh.',
    );
  });

  it('never repeats a word, has no em-dash and no API path, technical or plain', () => {
    for (const c of copies) {
      for (const s of [c.title, c.body, plainWords(c.title), plainWords(c.body)]) {
        expect(s).not.toMatch(/\b(\w+) \1\b/i);
        expect(s).not.toContain('—');
        expect(s).not.toContain('/api/');
      }
    }
  });
});
