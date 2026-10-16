import { describe, expect, it } from 'vitest';
import { SETUP_RUN_STAGES } from '../../../../../shared/contracts/edgeCodes';
import { PLAIN_STAGES, plainStage, runIsLive } from './runStages';

describe('plainStage', () => {
  it('folds every machine stage onto the four plain ones', () => {
    for (const s of SETUP_RUN_STAGES) expect(plainStage(s)).toBeGreaterThanOrEqual(1);
    expect(plainStage('prepare')).toBe(1);
    expect(plainStage('provision')).toBe(1);
    expect(plainStage('verify')).toBe(2);
    expect(plainStage('try_it')).toBe(3);
    // An enrolled node waits for its go-live approval at publish: "Going live".
    expect(plainStage('publish')).toBe(4);
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
