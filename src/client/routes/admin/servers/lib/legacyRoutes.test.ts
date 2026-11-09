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
  ['/admin/servers/origins', '', '/admin/servers/nodes?columns=technical'],
  [
    '/admin/servers/origins',
    '?filter=attention&layer=l7',
    '/admin/servers/nodes?columns=technical&show=attention&layer=l7',
  ],
  ['/admin/servers/origins', '?filter=all&layer=all', '/admin/servers/nodes?columns=technical'],
  ['/admin/servers/origins', '?filter=dark', '/admin/servers/nodes?columns=technical&show=dark'],
  ['/admin/servers/origins', '?new=1', '/admin/servers/nodes?columns=technical&add=origin'],
  ['/admin/servers/origins/', '?x=1', '/admin/servers/nodes?columns=technical&x=1'],
  // The old Edges section.
  ['/admin/edges', '', '/admin/servers/nodes?show=fronted'],
  ['/admin/edges/', '?protect=1&server=p&node=u', '/admin/servers/nodes?backend=p&front=1&node=u'],
  ['/admin/edges', '?protect=1', '/admin/servers/nodes?front=1'],
  ['/admin/edges', '?run=r1', '/admin/servers/nodes?run=r1'],
  ['/admin/edges/nodes/node-a', '?test=e1', '/admin/servers/origins/node-a?test=e1'],
  ['/admin/edges/advanced', '', '/admin/servers'],
  [
    '/admin/edges/advanced/origins',
    '?filter=x&layer=l7',
    '/admin/servers/nodes?columns=technical&layer=l7',
  ],
  [
    '/admin/edges/advanced/origins',
    '?filter=quarantined',
    '/admin/servers/nodes?columns=technical&show=quarantined',
  ],
  ['/admin/edges/advanced/origins', '?new=1', '/admin/servers/nodes?columns=technical&add=origin'],
  ['/admin/edges/advanced/relays', '', '/admin/servers/nodes?columns=technical'],
  ['/admin/edges/setup', '', '/admin/servers/nodes?columns=technical'],
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
  ['/admin/edges/settings', '?section=delivery', '/admin/servers/settings?section=delivery'],
  ['/admin/edges/names', '', '/admin/servers/snis'],
  ['/admin/edges/names/fam-a', '', '/admin/servers/snis/lists/fam-a'],
  // An SNI list may be called "find": it never lands on Find more.
  ['/admin/edges/names/find', '', '/admin/servers/snis/lists/find'],
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
    ['/admin/servers/nodes', '?columns=technical'],
    ['/admin/servers/origins/o1', ''],
    ['/admin/servers/origins/o1/details', '?tab=edges'],
    ['/admin/servers/settings', '?section=probes'],
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
