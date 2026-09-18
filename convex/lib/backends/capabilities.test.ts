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
    // Host management = list + repoint + create + delete (the relay Host flip,
    // the rotation machine's `ensureListenerHost` and the delete cleanup).
    expect(caps.hostManagement).toBe(
      !!provider.listHosts &&
        !!provider.updateHost &&
        !!provider.createHost &&
        !!provider.deleteHost,
    );
    expect(!!provider.createHost).toBe(!!provider.deleteHost);
    expect(caps.nodeInventory).toBe(!!provider.getNodeInventory);
    expect(caps.hostDisable).toBe(!!provider.setHostDisabled);
    expect(caps.inboundDiscovery).toBe(!!provider.listNodeInbounds);
    // Hiding a Host is only meaningful where FCP manages Hosts at all.
    if (caps.hostDisable) expect(caps.hostManagement).toBe(true);
  });
});
