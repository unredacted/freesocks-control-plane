import { describe, expect, it } from 'vitest';
import type { AttentionItem, SetupRunAdmin } from '../../../../../shared/contracts/edges';
import { SETUP_RUN_STAGES } from '../../../../../shared/contracts/edgeCodes';
import { PLAIN_STAGES, fleetSentence, nodeStatus, plainStage, runIsLive } from './nodeStatus';

const relay = (over: Partial<Parameters<typeof nodeStatus>[0]['relay']> = {}) => ({
  slug: 'node-a',
  enabled: true,
  quarantine: null,
  restore: null,
  deleting: false,
  bindingDeferred: false,
  setupOwned: false,
  publishedCount: 1,
  ...over,
});
const row = (
  over: Partial<Parameters<typeof nodeStatus>[0]['relay']> = {},
  pool: Array<{ health: string }> = [{ health: 'online' }],
  standbys = 0,
) => ({ relay: relay(over), pool, standbys });
const run = (over: Partial<SetupRunAdmin>): SetupRunAdmin =>
  ({ relaySlug: 'node-a', stage: 'provision', state: 'running', ...over }) as SetupRunAdmin;
const item = (over: Partial<AttentionItem>): AttentionItem =>
  ({ relaySlug: 'node-a', kind: 'block_suspected', severity: 'warning', ...over }) as AttentionItem;
const ctx = { attention: [], runs: [] };

describe('plainStage', () => {
  it('folds every machine stage onto the four plain ones', () => {
    for (const s of SETUP_RUN_STAGES) expect(plainStage(s)).toBeGreaterThanOrEqual(1);
    expect(plainStage('prepare')).toBe(1);
    expect(plainStage('provision')).toBe(1);
    expect(plainStage('verify')).toBe(2);
    expect(plainStage('try_it')).toBe(3);
    expect(plainStage('publish')).toBe(3);
    expect(plainStage('go_live')).toBe(4);
    expect(plainStage('done')).toBe(5);
    expect(PLAIN_STAGES.length).toBe(4);
  });
  it('knows which runs are live', () => {
    expect(runIsLive({ state: 'waiting' })).toBe(true);
    expect(runIsLive({ state: 'needs_you' })).toBe(true);
    expect(runIsLive({ state: 'done_unbound' })).toBe(false);
  });
});

describe('nodeStatus', () => {
  it('reads a live run first', () => {
    expect(nodeStatus(row(), { attention: [], runs: [run({})] })).toMatchObject({
      kind: 'setting-up',
      step: 1,
      sentence: 'Setting up, step 1 of 4.',
    });
    expect(
      nodeStatus(row(), { attention: [], runs: [run({ state: 'needs_you', stage: 'try_it' })] }),
    ).toMatchObject({ kind: 'needs-you', dot: 'amber', step: 3 });
    expect(nodeStatus(row(), { attention: [], runs: [run({ state: 'failed' })] }).kind).toBe(
      'protected',
    );
  });
  it('orders the rest: removing, paused, attention, off, not live, empty, offline, protected', () => {
    expect(nodeStatus(row({ restore: { phase: 'settle' } as never }), ctx).kind).toBe('removing');
    expect(nodeStatus(row({ quarantine: {} as never }), ctx)).toMatchObject({
      kind: 'paused',
      dot: 'red',
    });
    expect(
      nodeStatus(row(), { attention: [item({ severity: 'critical' })], runs: [] }),
    ).toMatchObject({ kind: 'needs-you', dot: 'red', sentence: 'Block suspected. It needs you.' });
    expect(nodeStatus(row(), { attention: [item({ severity: 'info' })], runs: [] }).kind).toBe(
      'protected',
    );
    expect(nodeStatus(row({ enabled: false }), ctx).kind).toBe('off');
    expect(nodeStatus(row({ bindingDeferred: true }), ctx)).toMatchObject({
      kind: 'not-live',
      dot: 'amber',
    });
    expect(nodeStatus(row({ publishedCount: 0 }, []), ctx).kind).toBe('unprotected');
    expect(nodeStatus(row({}, [{ health: 'offline' }]), ctx).sentence).toBe(
      '1 address is offline.',
    );
    expect(nodeStatus(row({ publishedCount: 2 }, [{ health: 'online' }], 1), ctx).sentence).toBe(
      'Protected. 2 addresses in use, 1 spare.',
    );
  });
});

describe('fleetSentence', () => {
  const s = (kind: string) => ({ kind, dot: 'green', sentence: '' }) as never;
  it('says the one thing that matters most', () => {
    expect(fleetSentence([])).toMatchObject({ text: 'No node is protected yet.', dot: 'grey' });
    expect(fleetSentence([s('protected'), s('protected')])).toMatchObject({
      text: 'All 2 nodes protected.',
      dot: 'green',
    });
    expect(fleetSentence([s('protected')]).text).toBe('Your node is protected.');
    expect(fleetSentence([s('protected'), s('needs-you')]).text).toBe('1 node needs you.');
    expect(fleetSentence([s('protected'), s('setting-up')]).text).toBe('Setting up 1 node.');
    expect(fleetSentence([s('protected'), s('not-live')]).text).toBe('1 node is not live yet.');
    expect(fleetSentence([s('protected'), s('off')]).text).toBe('1 of 2 nodes protected.');
  });
});
