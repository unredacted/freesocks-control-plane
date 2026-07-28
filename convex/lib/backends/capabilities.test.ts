/**
 * The capability record is the DB-side mirror of the provider layer's optional
 * methods. This suite is the drift guard: a provider gaining/losing an
 * optional op without the capability row following (or vice versa) fails here,
 * not in production behavior.
 */
import { describe, expect, test } from 'vitest';
import { BACKEND_IDS } from '../backendIds';
import { CAPABILITIES } from './capabilities';
import { PROVIDERS } from './registry';

describe('capability record ⇔ provider methods', () => {
  test('every backend id has a capability row', () => {
    for (const id of BACKEND_IDS) expect(CAPABILITIES[id]).toBeDefined();
  });

  test.each([...BACKEND_IDS])('%s: flags mirror the optional provider ops', (id) => {
    const caps = CAPABILITIES[id];
    const provider = PROVIDERS[id];
    expect(caps.deviceManagement).toBe(!!provider.removeDevice);
    expect(caps.bulkTrafficUpdate).toBe(!!provider.bulkUpdateTrafficLimit);
    expect(caps.usageHistory).toBe(!!provider.getUserUsage);
    expect(caps.nodeStats).toBe(!!provider.getNodeStats);
  });
});
