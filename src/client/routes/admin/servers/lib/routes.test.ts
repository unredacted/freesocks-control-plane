import { describe, expect, test } from 'vitest';
import {
  instanceSlugOf,
  legacyServersRedirect,
  nodeHomeOf,
  pickInstance,
  resolveServersRoute,
  serversPaths,
  serversTabOf,
} from './routes';

describe('the Servers leaf', () => {
  test('three tabs and the node page resolve; anything else is not found', () => {
    expect(resolveServersRoute('/admin/servers')).toEqual({ page: 'home' });
    expect(resolveServersRoute('/admin/servers/')).toEqual({ page: 'home' });
    expect(resolveServersRoute('/admin/servers/backends')).toEqual({ page: 'backends' });
    expect(resolveServersRoute('/admin/servers/pools')).toEqual({ page: 'pools' });
    expect(resolveServersRoute('/admin/servers/nodes/uuid-1')).toEqual({
      page: 'node',
      uuid: 'uuid-1',
    });
    expect(resolveServersRoute('/admin/servers/nodes')).toEqual({ page: 'not-found' });
    expect(resolveServersRoute('/admin/servers/nope')).toEqual({ page: 'not-found' });
  });

  test('every path builder lands on its own page', () => {
    expect(resolveServersRoute(serversPaths.home()).page).toBe('home');
    expect(serversPaths.home({ instance: 'panel a' })).toBe('/admin/servers?instance=panel%20a');
    expect(resolveServersRoute(serversPaths.backends()).page).toBe('backends');
    expect(resolveServersRoute(serversPaths.pools()).page).toBe('pools');
    const node = serversPaths.node('u/1', { instance: 'p' });
    expect(node).toBe('/admin/servers/nodes/u%2F1?instance=p');
    expect(resolveServersRoute(node.split('?')[0]!)).toEqual({ page: 'node', uuid: 'u/1' });
    expect(serversPaths.node('u1', { instance: 'p', test: 'e 1' })).toBe(
      '/admin/servers/nodes/u1?instance=p&test=e%201',
    );
    expect(serversPaths.node('u1', { test: 'e1' })).toBe('/admin/servers/nodes/u1?test=e1');
  });

  test('the tab a page lights up: a node page belongs to Nodes', () => {
    expect(serversTabOf({ page: 'backends' })).toBe('backends');
    expect(serversTabOf({ page: 'pools' })).toBe('pools');
    expect(serversTabOf({ page: 'home' })).toBe('nodes');
    expect(serversTabOf({ page: 'node', uuid: 'x' })).toBe('nodes');
    expect(serversTabOf({ page: 'not-found' })).toBe('nodes');
  });
});

describe('old addresses redirect to their tab', () => {
  test('Backend servers and Remnawave, with the search string kept', () => {
    expect(legacyServersRedirect('/admin/backend-servers')).toBe('/admin/servers/backends');
    expect(legacyServersRedirect('/admin/backend-servers/', '?x=1')).toBe(
      '/admin/servers/backends?x=1',
    );
    expect(legacyServersRedirect('/admin/remnawave')).toBe('/admin/servers/pools');
    expect(legacyServersRedirect('/admin/remnawave', '?a=b')).toBe('/admin/servers/pools?a=b');
  });

  test('every target is a page of the section; nothing else moves', () => {
    for (const p of ['/admin/backend-servers', '/admin/remnawave'])
      expect(resolveServersRoute(legacyServersRedirect(p)!).page).not.toBe('not-found');
    for (const p of ['/admin/servers', '/admin/connection-modes', '/admin/edges', '/admin'])
      expect(legacyServersRedirect(p)).toBeNull();
  });
});

describe('instances', () => {
  const list = [
    { id: 'id-a', slug: 'a', observable: false },
    { id: 'id-b', slug: 'b', observable: true },
  ];
  test('the URL picks, else the first observable one', () => {
    expect(pickInstance('?instance=a', list)).toBe('a');
    expect(pickInstance('?instance=zz', list)).toBe('b');
    expect(pickInstance('', [])).toBeNull();
  });
  test('a backend server id names its slug', () => {
    expect(instanceSlugOf(list, 'id-b')).toBe('b');
    expect(instanceSlugOf(list, 'id-x')).toBeNull();
    expect(instanceSlugOf(undefined, 'id-b')).toBeNull();
  });
});

describe('/admin/edges/nodes/<slug> redirects to the node\'s one page', () => {
  const instances = [{ id: 'sid-1', slug: 'panel-a' }];
  test('a backend node goes to its Servers node page, keeping the test card', () => {
    const origin = {
      kind: 'panel-node' as const,
      backendServerId: 'sid-1',
      nodeName: 'node-a',
      nodeUuid: 'uuid-a',
    };
    expect(nodeHomeOf(origin, instances)).toBe('/admin/servers/nodes/uuid-a?instance=panel-a');
    expect(nodeHomeOf(origin, instances, undefined, 'edge-1')).toBe(
      '/admin/servers/nodes/uuid-a?instance=panel-a&test=edge-1',
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
      '/admin/servers/nodes/uuid-a?instance=panel-a',
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
