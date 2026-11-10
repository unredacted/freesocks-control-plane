import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, tick, unmount, type Component } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { router } from '@client/stores/router.svelte';
import { mountWithQuery } from '../../../testing/mountWithQuery';
import NodePage from './NodePage.svelte';
import RelayPage from '../edges/RelayPage.svelte';
import OriginPage from '../edges/simple/NodePage.svelte';

/**
 * A node's page end to end against canned API answers: the section bar, the
 * fold closed by default, and the old origin details address finding the
 * node page (or an origin added by hand's own page) at runtime.
 */
vi.hoisted(() => {
  window.matchMedia ??= ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener() {},
    removeEventListener() {},
    addListener() {},
    removeListener() {},
    dispatchEvent: () => false,
  })) as never;
  Element.prototype.scrollIntoView ??= () => {};
});

const NOW = '2026-11-09T00:00:00.000Z';
const state = { observedAt: NOW, attemptedAt: NOW, ok: true, errorCode: null, counts: null };
const relay = (slug: string, origin: unknown) => ({
  id: `id-${slug}`,
  slug,
  label: null,
  origin,
  originAddress: 'x',
  locationCode: null,
  hostMode: 'none',
  enabled: true,
  autoRotate: true,
  publishedCount: 1,
  desiredPublished: 2,
  publishedEdgeIds: [],
  standbyEdgeIds: [],
  quarantine: null,
  deleting: false,
  activeRotationId: null,
  suspicion: null,
  qualificationCredential: false,
});
const fronted = relay('node-a', {
  kind: 'panel-node',
  backendServerId: 'b-1',
  nodeName: 'node-a',
  nodeUuid: 'n-1',
});
const manual = relay('office-box', { kind: 'manual' });

const ANSWERS: Record<string, unknown> = {
  '/api/v1/admin/servers/summary': {
    config: { 'manage.observe': true, 'manage.enabled': false },
    instances: [
      {
        ...state,
        id: 'b-1',
        slug: 'panel-a',
        name: 'Panel A',
        backend: 'remnawave',
        isActive: true,
        observable: true,
        writable: true,
        setUp: true,
      },
    ],
  },
  '/api/v1/admin/servers/panel-a/tree': {
    instance: { id: 'b-1', slug: 'panel-a', name: 'Panel A' },
    observable: true,
    state,
    nodes: [
      {
        nodeUuid: 'n-1',
        name: 'node-a',
        address: null,
        port: null,
        countryCode: 'NL',
        online: true,
        isDisabled: false,
        usersOnline: 7,
        tags: [],
        xrayVersion: null,
        frontKeys: null,
        profile: { profileUuid: 'p', name: 'Default', transportCount: 1, changedAt: null },
        transports: [
          {
            tag: 'reality-in',
            transportUuid: 't-1',
            protocol: 'vless',
            port: 443,
            listen: null,
            network: 'raw',
            security: 'reality',
            serverNames: ['a.example'],
            realityTarget: null,
            tlsServerName: null,
            path: null,
            serviceName: null,
            realityPublicKey: null,
            realityPublicKeyMismatch: false,
            addresses: [],
            modeGroups: [{ groupUuid: 'g', name: 'free-group' }],
            realityRefusal: null,
          },
        ],
      },
    ],
    profiles: [],
    modeGroups: [],
    addresses: [],
    unattached: { profiles: [], addresses: [] },
  },
  '/api/v1/admin/servers/panel-a/nodes/intents': { intents: [], holds: [] },
  '/api/v1/admin/servers/panel-a/renames': { renames: [] },
  '/api/v1/admin/servers/panel-a/port-changes': { changes: [] },
  '/api/v1/admin/edges/summary': {
    counts: {},
    relays: [
      { relay: fronted, pool: [], standbys: 0, draining: 0, needsOperator: 0, rotation: null },
    ],
    generatedAt: NOW,
  },
  '/api/v1/admin/edges/relays/lookup?slug=node-a': fronted,
  '/api/v1/admin/edges/relays/lookup?slug=office-box': manual,
};

const failing = new Set<string>();

vi.mock('@client/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/api')>()),
  apiClient: {
    get: (path: string) =>
      path in ANSWERS && !failing.has(path)
        ? Promise.resolve(ANSWERS[path])
        : // A failure takes a moment, as over the network.
          new Promise((_, reject) => setTimeout(() => reject(new Error(`no ${path}`)), 5)),
    post: () => Promise.reject(new Error('no writes')),
    patch: () => Promise.reject(new Error('no writes')),
    put: () => Promise.reject(new Error('no writes')),
    delete: () => Promise.reject(new Error('no writes')),
  },
}));

let app: ReturnType<typeof mountWithQuery> | null = null;

async function mount(url: string, component: Component<never>, props: object): Promise<string> {
  router.navigate(url, { replace: true });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  app = mountWithQuery(client, component, props as never);
  for (let i = 0; i < 12; i++) {
    await new Promise((r) => setTimeout(r, 0));
    await tick();
  }
  flushSync();
  return (document.body.textContent ?? '').replace(/\s+/g, ' ');
}

afterEach(() => {
  failing.clear();
  vi.restoreAllMocks();
  if (app) unmount(app);
  app = null;
  document.body.innerHTML = '';
});

describe('the node page', () => {
  test('a section bar over one scroll; Technical details closed by default', async () => {
    const text = await mount('/admin/servers/nodes/n-1?backend=panel-a', NodePage as never, {
      uuid: 'n-1',
    });
    const bar = document.querySelector('nav[aria-label="Sections"]')!;
    expect([...bar.querySelectorAll('a')].map((a) => a.textContent?.trim())).toEqual([
      'Summary',
      'Addresses',
      'Transports',
      'SNIs',
      'Modes',
      'Activity',
      'Technical details',
    ]);
    for (const id of ['summary', 'addresses', 'transports', 'snis', 'modes', 'activity', 'details'])
      expect(document.getElementById(`node-${id}`), id).not.toBeNull();
    expect(text).toContain('Online, 7 people connected.');
    expect(text).toContain('Runs the profile Default.');
    expect(text).toContain('free-group');
    const fold = [...document.querySelectorAll('button')].find((b) =>
      b.textContent?.includes('Technical details'),
    )!;
    expect(fold.getAttribute('aria-expanded')).toBe('false');
  });

  test('?section=details opens the fold', async () => {
    await mount('/admin/servers/nodes/n-1?backend=panel-a&section=details', NodePage as never, {
      uuid: 'n-1',
    });
    const fold = [...document.querySelectorAll('button')].find((b) =>
      b.textContent?.includes('Technical details'),
    )!;
    expect(fold.getAttribute('aria-expanded')).toBe('true');
  });
});

describe('a fronted transport: what members get', () => {
  const TREE = '/api/v1/admin/servers/panel-a/tree';
  const SUMMARY = '/api/v1/admin/servers/summary';
  const SNI = '/api/v1/admin/edges/sni/transports?backend=panel-a';
  const address = (remark: string, over: Record<string, unknown> = {}) => ({
    addressUuid: `h-${remark}`,
    remark,
    address: `${remark}.example`,
    port: 443,
    sni: 'template-sni.example',
    host: null,
    path: null,
    alpn: null,
    fingerprint: null,
    securityLayer: null,
    isDisabled: false,
    isHidden: false,
    tag: null,
    viewPosition: 0,
    configProfileUuid: 'p',
    transportUuid: 't-1',
    nodeUuids: [],
    operatorFront: false,
    fcpOwned: false,
    ...over,
  });
  const managed = {
    switches: {
      names: true,
      findNames: false,
      backendChanges: true,
      backendSetUp: true,
      autoTest: 'off',
    },
    transports: [
      {
        transportUuid: 't-1',
        tag: 'reality-in',
        profileUuid: 'p',
        profileName: 'Default',
        port: 443,
        coverSite: 'cover.example:443',
        listed: 1,
        profileNodes: [{ nodeUuid: 'n-1', name: 'node-a' }],
        list: {
          slug: 'shared-cover',
          label: 'Shared cover',
          enabled: true,
          bindingId: 'bind-1',
          counts: {
            inUse: 1,
            waitingTest: 0,
            toSend: 0,
            idle: 0,
            checking: 0,
            failing: 0,
            off: 0,
          },
          suggestions: 0,
        },
        send: null,
        nodes: [],
        sameCoverSite: [],
      },
    ],
  };
  type Tree = { nodes: { transports: { addresses: unknown[]; security: string }[] }[] };
  const saved = { tree: '', summary: '' };

  /** The page with these addresses on the node's one transport, changes allowed. */
  async function page(addresses: unknown[], over: { security?: string; sni?: unknown } = {}) {
    saved.tree = JSON.stringify(ANSWERS[TREE]);
    saved.summary = JSON.stringify(ANSWERS[SUMMARY]);
    const tree = JSON.parse(saved.tree) as Tree;
    tree.nodes[0]!.transports[0]!.addresses = addresses;
    if (over.security) tree.nodes[0]!.transports[0]!.security = over.security;
    ANSWERS[TREE] = tree;
    const summary = JSON.parse(saved.summary) as { config: Record<string, boolean> };
    summary.config['manage.enabled'] = true;
    ANSWERS[SUMMARY] = summary;
    if (over.sni !== undefined) ANSWERS[SNI] = over.sni;
    await mount('/admin/servers/nodes/n-1?backend=panel-a', NodePage as never, { uuid: 'n-1' });
    const section = document.getElementById('node-transports')!;
    return {
      section,
      text: (section.textContent ?? '').replace(/\s+/g, ' '),
      line: section.querySelector('[data-testid="fronted-addresses"]'),
      buttons: [...section.querySelectorAll('button')].map((b) => b.textContent?.trim()),
    };
  }
  afterEach(() => {
    ANSWERS[TREE] = JSON.parse(saved.tree);
    ANSWERS[SUMMARY] = JSON.parse(saved.summary);
    delete ANSWERS[SNI];
  });

  test("the Host FCP keeps is not an address to edit: one line says the node's addresses and its SNI list", async () => {
    const p = await page([address('node-a-relay', { fcpOwned: true })], { sni: managed });
    expect(p.line?.textContent?.replace(/\s+/g, ' ').trim()).toBe(
      "One of this node's addresses above, with an SNI from the SNI list Shared cover.",
    );
    // The template's own remark, address and SNI are not shown as what members get.
    expect(p.text).not.toContain('node-a-relay');
    expect(p.text).not.toContain('template-sni.example');
    expect(p.text).not.toContain('None yet.');
    expect(p.buttons).not.toContain('node-a-relay');
    const links = [...p.line!.querySelectorAll('a')].map((a) => [
      a.textContent?.trim(),
      a.getAttribute('href'),
    ]);
    expect(links).toEqual([
      ["this node's addresses above", '#node-addresses'],
      ['Shared cover', '/admin/servers/snis/lists/shared-cover'],
    ]);
    // The first link goes to the Addresses section of this page.
    p.line!.querySelector('a')!.click();
    await tick();
    expect(router.search).toContain('section=addresses');
  });

  test('no SNI list manages the transport: the line points at the SNIs section', async () => {
    const p = await page([address('node-a-relay', { fcpOwned: true })]);
    expect(p.line?.textContent?.replace(/\s+/g, ' ').trim()).toBe(
      "One of this node's addresses above, with one of its SNIs.",
    );
    expect([...p.line!.querySelectorAll('a')].map((a) => a.getAttribute('href'))).toEqual([
      '#node-addresses',
      '#node-snis',
    ]);
  });

  test('a transport without SNIs says the addresses only', async () => {
    const p = await page([address('node-a-relay', { fcpOwned: true })], { security: 'tls' });
    expect(p.line?.textContent?.replace(/\s+/g, ' ').trim()).toBe(
      "One of this node's addresses above.",
    );
  });

  test('addresses made by hand and the operator fronts stay as they were', async () => {
    const p = await page(
      [
        address('node-a-relay', { fcpOwned: true }),
        address('by-hand'),
        address('own-lb', { operatorFront: true }),
      ],
      { sni: managed },
    );
    expect(p.line).not.toBeNull();
    expect(p.buttons).toEqual(expect.arrayContaining(['by-hand', 'own-lb', 'Add an address']));
    expect(p.buttons).not.toContain('node-a-relay');
    expect(p.text).toContain("Your own fronts, left out of members' subscriptions");
  });

  test('a node nothing fronts lists its addresses as before, with no line', async () => {
    const p = await page([address('by-hand')]);
    expect(p.line).toBeNull();
    expect(p.buttons).toContain('by-hand');
    expect(p.text).toContain('by-hand.example:443 · template-sni.example');
  });
});

describe('review fixes', () => {
  test('a failed edge summary read is an error with Retry, never "reach this node directly"', async () => {
    failing.add('/api/v1/admin/edges/summary');
    await mount('/admin/servers/nodes/n-1?backend=panel-a', NodePage as never, { uuid: 'n-1' });
    for (let i = 0; i < 5; i++) {
      await new Promise((r) => setTimeout(r, 20));
      await tick();
    }
    const text = (document.body.textContent ?? '').replace(/\s+/g, ' ');
    expect(text).toContain('Whether anything fronts this node could not be read yet.');
    expect(text).not.toContain('Members reach this node directly');
    expect(text).not.toContain('Front this node');
    expect(text).not.toContain('Nothing fronts this node');
    const buttons = [...document.querySelectorAll('button')].map((b) => b.textContent ?? '');
    expect(buttons.some((b) => /Retry|Try again/.test(b))).toBe(true);
  });

  test('a link that names a section later still scrolls there', async () => {
    const scroll = vi.spyOn(Element.prototype, 'scrollIntoView').mockImplementation(() => {});
    await mount('/admin/servers/nodes/n-1?backend=panel-a', NodePage as never, { uuid: 'n-1' });
    expect(scroll).not.toHaveBeenCalled();
    router.navigate('/admin/servers/nodes/n-1?backend=panel-a&section=details');
    for (let i = 0; i < 5; i++) {
      await new Promise((r) => setTimeout(r, 20));
      await tick();
    }
    expect(scroll).toHaveBeenCalled();
    expect((scroll.mock.contexts.at(-1) as HTMLElement).id).toBe('node-details');
  });
});

describe('the old origin details address', () => {
  test('a backend node lands on its node page, the tab in the fold', async () => {
    await mount('/admin/servers/origins/node-a/details?tab=edges&edge=e1', RelayPage as never, {
      slug: 'node-a',
    });
    expect(router.pathname).toBe('/admin/servers/nodes/n-1');
    expect(router.search).toBe('?backend=panel-a&section=details&tab=edges&edge=e1');
  });

  test('the Overview tab lands on Summary', async () => {
    await mount('/admin/servers/origins/node-a/details?tab=overview', RelayPage as never, {
      slug: 'node-a',
    });
    expect(router.search).toBe('?backend=panel-a&section=summary');
  });

  test('an origin added by hand lands on its own page, which has the shorter bar', async () => {
    await mount('/admin/servers/origins/office-box/details', RelayPage as never, {
      slug: 'office-box',
    });
    expect(router.pathname).toBe('/admin/servers/origins/office-box');
    expect(router.search).toBe('?section=details');
    unmount(app!);
    app = null;
    document.body.innerHTML = '';
    const text = await mount('/admin/servers/origins/office-box', OriginPage as never, {
      slug: 'office-box',
    });
    expect(text).toContain('Added by hand');
    const bar = document.querySelector('nav[aria-label="Sections"]')!;
    expect([...bar.querySelectorAll('a')].map((a) => a.textContent?.trim())).toEqual([
      'Summary',
      'Addresses',
      'Activity',
      'Technical details',
    ]);
  });
});
