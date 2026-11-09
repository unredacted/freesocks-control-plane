import { describe, expect, test } from 'vitest';
import {
  instanceSlugOf,
  nodeHomeOf,
  pickInstance,
  resolveSectionRoute,
  resolveServersRoute,
  serversPaths,
  SERVERS_TABS,
  tabOf,
} from './routes';
import { edgesPaths } from '../../edges/lib/routes';

describe('the Servers section', () => {
  test("its own pages resolve; anything else is the Edges pages' to resolve", () => {
    expect(resolveServersRoute('/admin/servers/nodes')).toEqual({ page: 'nodes' });
    expect(resolveServersRoute('/admin/servers/nodes/')).toEqual({ page: 'nodes' });
    expect(resolveServersRoute('/admin/servers/settings/backends')).toEqual({ page: 'backends' });
    expect(resolveServersRoute('/admin/servers/settings/mode-pools')).toEqual({ page: 'pools' });
    expect(resolveServersRoute('/admin/servers/nodes/uuid-1')).toEqual({
      page: 'node',
      uuid: 'uuid-1',
    });
    for (const p of ['/admin/servers', '/admin/servers/backends', '/admin/servers/pools'])
      expect(resolveServersRoute(p)).toEqual({ page: 'not-found' });
  });

  test('every path builder lands on its own page', () => {
    expect(serversPaths.overview()).toBe('/admin/servers');
    expect(serversPaths.nodes()).toBe('/admin/servers/nodes');
    expect(serversPaths.nodes({ backend: 'panel a' })).toBe(
      '/admin/servers/nodes?backend=panel%20a',
    );
    expect(resolveServersRoute(serversPaths.nodes()).page).toBe('nodes');
    expect(resolveServersRoute(serversPaths.backends()).page).toBe('backends');
    expect(resolveServersRoute(serversPaths.pools()).page).toBe('pools');
    const node = serversPaths.node('u/1', { backend: 'p' });
    expect(node).toBe('/admin/servers/nodes/u%2F1?backend=p');
    expect(resolveServersRoute(node.split('?')[0]!)).toEqual({ page: 'node', uuid: 'u/1' });
    expect(serversPaths.node('u1', { backend: 'p', test: 'e 1' })).toBe(
      '/admin/servers/nodes/u1?backend=p&test=e%201',
    );
    expect(serversPaths.node('u1', { test: 'e1' })).toBe('/admin/servers/nodes/u1?test=e1');
  });

  test('seven tabs, and the tab each page lights up', () => {
    expect(SERVERS_TABS).toEqual([
      'overview',
      'nodes',
      'countries',
      'snis',
      'probes',
      'providers',
      'settings',
    ]);
    const tab = (path: string) => tabOf(resolveSectionRoute(path));
    expect(tab(serversPaths.overview())).toBe('overview');
    expect(tab(serversPaths.nodes())).toBe('nodes');
    expect(tab(serversPaths.node('u1'))).toBe('nodes');
    expect(tab(edgesPaths.overview())).toBe('nodes');
    expect(tab(edgesPaths.node('o1'))).toBe('nodes');
    expect(tab(edgesPaths.relay('o1').split('?')[0]!)).toBe('nodes');
    expect(tab(edgesPaths.countries())).toBe('countries');
    expect(tab(edgesPaths.country('ir'))).toBe('countries');
    expect(tab(edgesPaths.lists())).toBe('countries');
    expect(tab(edgesPaths.list('l1'))).toBe('countries');
    expect(tab(edgesPaths.names())).toBe('snis');
    expect(tab(edgesPaths.family('f1'))).toBe('snis');
    expect(tab(edgesPaths.findNames())).toBe('snis');
    expect(tab(edgesPaths.findNetwork('n1'))).toBe('snis');
    expect(tab(edgesPaths.probes())).toBe('probes');
    expect(tab(edgesPaths.providers())).toBe('providers');
    expect(tab(edgesPaths.provider('a1'))).toBe('providers');
    expect(tab(edgesPaths.templates())).toBe('providers');
    expect(tab(edgesPaths.settings())).toBe('settings');
    expect(tab(serversPaths.backends())).toBe('settings');
    expect(tab(serversPaths.pools())).toBe('settings');
    expect(tab('/admin/servers/nope')).toBe('overview');
  });

  test('a page from either table resolves through one entry point', () => {
    expect(resolveSectionRoute('/admin/servers/nodes')).toEqual({
      from: 'servers',
      route: { page: 'nodes' },
    });
    expect(resolveSectionRoute('/admin/servers')).toEqual({
      from: 'edges',
      route: { page: 'home' },
    });
    expect(resolveSectionRoute('/admin/servers/nope')).toEqual({
      from: 'edges',
      route: { page: 'not-found' },
    });
  });
});

describe('instances', () => {
  const list = [
    { id: 'id-a', slug: 'a', observable: false },
    { id: 'id-b', slug: 'b', observable: true },
  ];
  test('the URL picks, else the first observable one', () => {
    expect(pickInstance('?backend=a', list)).toBe('a');
    expect(pickInstance('?backend=zz', list)).toBe('b');
    expect(pickInstance('', [])).toBeNull();
  });
  test('a backend server id names its slug', () => {
    expect(instanceSlugOf(list, 'id-b')).toBe('b');
    expect(instanceSlugOf(list, 'id-x')).toBeNull();
    expect(instanceSlugOf(undefined, 'id-b')).toBeNull();
  });
});

describe("an origin's page redirects to the node's one page", () => {
  const instances = [{ id: 'sid-1', slug: 'panel-a' }];
  test('a backend node goes to its Servers node page, keeping the test card', () => {
    const origin = {
      kind: 'panel-node' as const,
      backendServerId: 'sid-1',
      nodeName: 'node-a',
      nodeUuid: 'uuid-a',
    };
    expect(nodeHomeOf(origin, instances)).toBe('/admin/servers/nodes/uuid-a?backend=panel-a');
    expect(nodeHomeOf(origin, instances, undefined, 'edge-1')).toBe(
      '/admin/servers/nodes/uuid-a?backend=panel-a&test=edge-1',
    );
    expect(resolveServersRoute(nodeHomeOf(origin, instances)!.split('?')[0]!).page).toBe('node');
  });
  test('an older origin without a node uuid is found by name', () => {
    const origin = {
      kind: 'panel-node' as const,
      backendServerId: 'sid-1',
      nodeName: 'node-a',
      nodeUuid: null,
    };
    expect(nodeHomeOf(origin, instances)).toBeNull();
    expect(nodeHomeOf(origin, instances, [{ nodeUuid: 'uuid-a', name: 'node-a' }])).toBe(
      '/admin/servers/nodes/uuid-a?backend=panel-a',
    );
  });
  test('no Servers page: a manual or whole-server origin, or an unknown backend', () => {
    expect(nodeHomeOf({ kind: 'manual' }, instances)).toBeNull();
    expect(nodeHomeOf({ kind: 'backend-server', backendServerId: 'sid-1' }, instances)).toBeNull();
    expect(
      nodeHomeOf(
        { kind: 'panel-node', backendServerId: 'sid-x', nodeName: 'n', nodeUuid: 'u' },
        instances,
      ),
    ).toBeNull();
  });
});
