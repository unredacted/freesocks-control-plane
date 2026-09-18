import { describe, expect, it } from 'vitest';
import { inventoryOwner, isTested, settingLabel, settingRows, testWords } from './accountWords';

const NOW = Date.parse('2026-01-01T01:00:00.000Z');
const okAt = '2026-01-01T00:00:00.000Z';

describe('testWords', () => {
  it('covers never, passed and failed', () => {
    expect(testWords({ lastTestOkAt: null, lastTestError: null }, NOW).label).toBe('Never tested');
    expect(testWords({ lastTestOkAt: okAt, lastTestError: null }, NOW)).toMatchObject({
      label: 'Tested',
      detail: 'Passed 1 h ago',
    });
    const failed = testWords({ lastTestOkAt: okAt, lastTestError: 'auth_failed' }, NOW);
    expect(failed.tone).toBe('danger');
    expect(failed.detail).not.toContain('_');
    expect(isTested({ lastTestOkAt: okAt, lastTestError: 'x' })).toBe(false);
  });
});

describe('settings', () => {
  it('puts keys in words', () => {
    expect(settingLabel('projectId')).toBe('Project ID');
    expect(settingLabel('dnsAccountId')).toBe('DNS account ID');
    expect(settingLabel('zone_name')).toBe('Zone name');
  });
  it('names id-valued settings and drops empty ones', () => {
    const rows = settingRows(
      { region: 'r1', dnsAccountId: 'acc1', empty: '' },
      { acc1: 'Main DNS' },
    );
    expect(rows).toHaveLength(2);
    expect(rows[1]).toMatchObject({ label: 'DNS account ID', value: 'Main DNS', hint: 'acc1' });
  });
  it('marks unowned resources as foreign', () => {
    expect(inventoryOwner({ unowned: true })).toBe('foreign');
    expect(inventoryOwner({})).toBe('fcp');
  });
});
