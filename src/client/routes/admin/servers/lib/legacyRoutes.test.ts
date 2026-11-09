import { describe, expect, test } from 'vitest';
import { legacyRedirect } from './legacyRoutes';
import { resolveSectionRoute } from './routes';

/** Each old address, its search string, and where it must land. */
const RULES: ReadonlyArray<readonly [string, string, string]> = [
  // The Servers section's own moves.
  ['/admin/servers', '?instance=panel-a', '/admin/servers/nodes?backend=panel-a'],
  ['/admin/servers', '?instance=a&x=1', '/admin/servers/nodes?backend=a&x=1'],
  ['/admin/servers/nodes/u1', '?instance=p&test=e1', '/admin/servers/nodes/u1?backend=p&test=e1'],
  ['/admin/servers/backends', '', '/admin/servers/settings/backends'],
  ['/admin/servers/pools', '?a=b', '/admin/servers/settings/mode-pools?a=b'],
  ['/admin/backend-servers', '', '/admin/servers/settings/backends'],
  ['/admin/backend-servers/', '?x=1', '/admin/servers/settings/backends?x=1'],
  ['/admin/remnawave', '', '/admin/servers/settings/mode-pools'],
  ['/admin/telemetry/probes', '?range=7d', '/admin/servers/probes?range=7d'],
  // Settings: each old card opens the group that holds it now.
  ['/admin/servers/settings', '?section=basics', '/admin/servers/settings?group=automatic'],
  ['/admin/servers/settings', '?section=rotation', '/admin/servers/settings?group=replacement'],
  ['/admin/servers/settings', '?section=rendering', '/admin/servers/settings?group=subscriptions'],
  ['/admin/servers/settings', '?section=detector', '/admin/servers/settings?group=detection'],
  ['/admin/servers/settings', '?section=probes', '/admin/servers/settings?group=probes'],
  ['/admin/servers/settings', '?section=l7', '/admin/servers/settings?group=cdn-fronts'],
  ['/admin/servers/settings', '?section=names', '/admin/servers/settings?group=address-hostnames'],
  ['/admin/servers/settings', '?section=lists', '/admin/servers/settings?group=country-lists'],
  ['/admin/servers/settings', '?section=maintenance', '/admin/servers/settings?group=maintenance'],
  ['/admin/servers/settings', '?section=freedom', '/admin/servers/settings?group=delivery'],
  ['/admin/servers/settings', '?section=delivery', '/admin/servers/settings?group=delivery'],
  ['/admin/servers/settings', '?section=nope&q=drain', '/admin/servers/settings?q=drain'],
  [
    '/admin/servers/settings',
    '?group=probes&section=basics',
    '/admin/servers/settings?group=probes',
  ],
  // The old Edges section.
  ['/admin/edges', '', '/admin/servers'],
  ['/admin/edges/', '?protect=1&server=p&node=u', '/admin/servers?protect=1&server=p&node=u'],
  ['/admin/edges', '?run=r1', '/admin/servers?run=r1'],
  ['/admin/edges/nodes/node-a', '?test=e1', '/admin/servers/origins/node-a?test=e1'],
  ['/admin/edges/advanced', '', '/admin/servers'],
  [
    '/admin/edges/advanced/origins',
    '?filter=x&layer=l7',
    '/admin/servers/origins?filter=x&layer=l7',
  ],
  ['/admin/edges/advanced/origins', '?new=1', '/admin/servers/origins?new=1'],
  ['/admin/edges/advanced/relays', '', '/admin/servers/origins'],
  ['/admin/edges/setup', '', '/admin/servers/origins'],
  ['/admin/edges/setup', '?relay=r a', '/admin/servers/origins/r%20a/details'],
  ['/admin/edges/relays/relay-a', '', '/admin/servers/origins/relay-a/details'],
  [
    '/admin/edges/relays/relay-a',
    '?tab=edges&edge=e1',
    '/admin/servers/origins/relay-a/details?tab=edges&edge=e1',
  ],
  [
    '/admin/edges/providers',
    '?edit=new&provider=p',
    '/admin/servers/providers?edit=new&provider=p',
  ],
  ['/admin/edges/providers/acc1', '?tab=inventory', '/admin/servers/providers/acc1?tab=inventory'],
  ['/admin/edges/templates', '?template=t1', '/admin/servers/providers/templates?template=t1'],
  ['/admin/edges/probes', '?target=t', '/admin/servers/probes?target=t'],
  ['/admin/edges/settings', '', '/admin/servers/settings'],
  ['/admin/edges/settings', '?section=delivery', '/admin/servers/settings?group=delivery'],
  ['/admin/edges/settings', '?section=rotation', '/admin/servers/settings?group=replacement'],
  ['/admin/edges/names', '', '/admin/servers/snis'],
  ['/admin/edges/names/fam-a', '', '/admin/servers/snis/fam-a'],
  ['/admin/edges/find-names', '', '/admin/servers/snis/find'],
  ['/admin/edges/find-names/net-a', '', '/admin/servers/snis/find/net-a'],
  ['/admin/edges/countries', '', '/admin/servers/countries'],
  ['/admin/edges/countries/IR', '', '/admin/servers/countries/IR'],
  ['/admin/edges/countries/lists', '', '/admin/servers/countries/lists'],
  ['/admin/edges/countries/lists/l1', '', '/admin/servers/countries/lists/l1'],
];

describe('every moved address lands on its new page', () => {
  test.each(RULES)('%s%s -> %s', (path, search, to) => {
    expect(legacyRedirect(path, search)).toBe(to);
  });

  test('every target is a real page of the section', () => {
    for (const [path, search] of RULES) {
      const to = legacyRedirect(path, search)!;
      const r = resolveSectionRoute(to.split('?')[0]!);
      expect(r.route.page, to).not.toBe('not-found');
      // A target is never itself moved (no chains, no loops).
      const [p, q = ''] = to.split('?');
      expect(legacyRedirect(p!, q ? `?${q}` : ''), to).toBeNull();
    }
  });
});

describe('addresses that did not move', () => {
  test.each([
    ['/admin/servers', ''],
    ['/admin/servers', '?protect=1'],
    ['/admin/servers/nodes', '?backend=a'],
    ['/admin/servers/nodes/u1', '?backend=a'],
    ['/admin/servers/settings', '?group=probes'],
    ['/admin/servers/settings', '?field=drainMinutes'],
    ['/admin/connection-modes', ''],
    ['/admin/settings', ''],
    ['/admin', ''],
    ['/admin/edgesx', ''],
    // Not a page the old section had: not found, not guessed.
    ['/admin/edges/nope', ''],
  ])('%s%s stays', (path, search) => {
    expect(legacyRedirect(path, search)).toBeNull();
  });
});
