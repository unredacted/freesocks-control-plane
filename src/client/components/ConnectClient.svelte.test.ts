import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { queryKeys } from '@client/lib/queries';
import { mountWithQuery } from '../testing/mountWithQuery';
import ConnectClient from './ConnectClient.svelte';

const MAIN = 'https://site.example/api/v1/sub/token-1';
const MIRROR = 'https://cdn-1.example/mirrors/aaaa';
const ALL = ['android', 'ios', 'windows', 'desktop'];
const app = (name: string, schemeId: string | null, extra: Record<string, unknown> = {}) => ({
  name,
  platforms: ALL,
  backends: ['remnawave'],
  homepageUrl: `https://${name.toLowerCase()}.example`,
  schemeId,
  hwid: true,
  openSource: true,
  ...extra,
});

let client: QueryClient;
let mounted: ReturnType<typeof mountWithQuery> | null = null;
const props = $state<{
  subscriptionUrl: string;
  mirror?: { publicUrl: string; formats?: string[] } | null;
  modeId?: string;
  deviceLimited?: boolean;
}>({
  subscriptionUrl: MAIN,
});

beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(queryKeys.config, {
    clients: [
      app('Hiddify', 'hiddify', { format: 'links' }),
      app('sing-box', 'sing-box', { format: 'singbox' }),
      app('Clash', 'clash', { format: 'clash' }),
      // Paste only: no import button, so its own mirror link is all it has.
      app('FlClash', null, { format: 'clash' }),
    ],
    backends: { list: [] },
  });
  props.subscriptionUrl = MAIN;
  props.mirror = undefined;
  props.modeId = undefined;
  props.deviceLimited = undefined;
});
afterEach(() => {
  if (mounted) unmount(mounted);
  mounted = null;
  client.clear();
});

/**
 * Each app's "Open in" link, the mirror link its card shows to copy (if any)
 * and whether it says its mirror link is not ready yet.
 */
const cards = (): Record<string, { href: string | undefined; own: string | null; note: boolean }> =>
  Object.fromEntries(
    [...document.querySelectorAll('li')].map((li) => [
      li.querySelector('p')?.textContent?.trim() ?? '',
      {
        href: [...li.querySelectorAll('a')].find((a) => a.textContent?.includes('Open in'))?.href,
        own: li.querySelector('code')?.textContent?.trim() ?? null,
        note: li.textContent?.includes('still being set up') ?? false,
      },
    ]),
  );

describe('which link each app imports', () => {
  test('no pick: every app imports the main link, no notes', () => {
    mounted = mountWithQuery(client, ConnectClient, props);
    flushSync();
    const c = cards();
    expect(c['Hiddify']!.href).toContain(MAIN);
    expect(c['sing-box']!.href).toContain(encodeURIComponent(MAIN));
    expect(Object.values(c).some((x) => x.note)).toBe(false);
  });

  test('a mirror picked: every app imports it in its own format', () => {
    props.mirror = { publicUrl: MIRROR, formats: ['links', 'clash', 'singbox'] };
    mounted = mountWithQuery(client, ConnectClient, props);
    flushSync();
    const c = cards();
    expect(c['Hiddify']!.href).toContain(MIRROR);
    expect(c['Hiddify']!.href).not.toContain(`${MIRROR}.`);
    // The pass shows the plain link: a link-list app needs no link of its own.
    expect(c['Hiddify']!.own).toBeNull();
    expect(c['sing-box']!.href).toContain(encodeURIComponent(`${MIRROR}.json`));
    expect(c['sing-box']!.own).toBe(`${MIRROR}.json`);
    expect(c['Clash']!.href).toContain(encodeURIComponent(`${MIRROR}.yaml`));
    expect(c['Clash']!.own).toBe(`${MIRROR}.yaml`);
    // An app with no import button gets the link to paste.
    expect(c['FlClash']!.href).toBeUndefined();
    expect(c['FlClash']!.own).toBe(`${MIRROR}.yaml`);
    expect(Object.values(c).some((x) => x.note)).toBe(false);
  });

  test('a mirror from before formats: apps of another format keep the main link, and say why', () => {
    props.mirror = { publicUrl: MIRROR, formats: ['links'] };
    mounted = mountWithQuery(client, ConnectClient, props);
    flushSync();
    const c = cards();
    expect(c['Hiddify']!.href).toContain(MIRROR);
    expect(c['Hiddify']!.note).toBe(false);
    for (const name of ['sing-box', 'Clash']) {
      expect(c[name]!.href).toContain(encodeURIComponent(MAIN));
      expect(c[name]!.href).not.toContain(encodeURIComponent(MIRROR));
      expect(c[name]!.own).toBeNull();
      expect(c[name]!.note).toBe(true);
    }
    expect(c['FlClash']!.note).toBe(true);
  });

  test('the main link picked: the same as no pick', () => {
    props.mirror = { publicUrl: MAIN, formats: ['links', 'clash', 'singbox'] };
    mounted = mountWithQuery(client, ConnectClient, props);
    flushSync();
    const c = cards();
    expect(c['Hiddify']!.href).toContain(MAIN);
    expect(Object.values(c).some((x) => x.note)).toBe(false);
  });
});

describe('which apps an XHTTP mode offers', () => {
  const XHTTP_LINE = 'Only apps that work with XHTTP are shown';
  // The app cards (the numbered steps are an <ol>).
  const names = () =>
    [...document.querySelectorAll('ul > li')].map((li) =>
      li.querySelector('p')?.textContent?.trim(),
    );
  const lineShown = () => document.body.textContent?.includes(XHTTP_LINE) ?? false;
  const pickTab = (key: string) => {
    document.querySelector<HTMLButtonElement>(`#connect-tab-${key}`)!.click();
    flushSync();
  };

  beforeEach(() => {
    client.setQueryData(queryKeys.config, {
      clients: [
        app('Hiddify', 'hiddify', { xhttp: true }),
        app('sing-box', 'sing-box', { xhttp: false }),
        app('Karing', 'karing', { xhttp: false, hwid: true }),
        // Untested: no flag.
        app('Shadowrocket', 'shadowrocket', { hwid: false }),
      ],
      backends: { list: [] },
    });
  });

  test('freedom-xhttp: apps that cannot use it are left out, untested ones stay, one line says why', () => {
    props.modeId = 'freedom-xhttp';
    mounted = mountWithQuery(client, ConnectClient, props);
    flushSync();
    expect(names()).toEqual(['Hiddify', 'Shadowrocket']);
    expect(lineShown()).toBe(true);
    // The first app left still carries the Recommended badge.
    expect(document.querySelector('li')?.textContent).toContain('Recommended');
  });

  test('another mode offers every app and says nothing', () => {
    props.modeId = 'freedom-reality';
    mounted = mountWithQuery(client, ConnectClient, props);
    flushSync();
    expect(names()).toEqual(['Hiddify', 'sing-box', 'Karing', 'Shadowrocket']);
    expect(lineShown()).toBe(false);
  });

  test('no mode yet: every app', () => {
    mounted = mountWithQuery(client, ConnectClient, props);
    flushSync();
    expect(names()).toHaveLength(4);
    expect(lineShown()).toBe(false);
  });

  test('the line shows only on a platform where something was left out', () => {
    client.setQueryData(queryKeys.config, {
      clients: [
        app('Hiddify', 'hiddify', { xhttp: true }),
        app('sing-box', 'sing-box', { xhttp: false, platforms: ['ios'] }),
      ],
      backends: { list: [] },
    });
    props.modeId = 'freedom-xhttp';
    mounted = mountWithQuery(client, ConnectClient, props);
    pickTab('windows');
    expect(names()).toEqual(['Hiddify']);
    expect(lineShown()).toBe(false);
    pickTab('ios');
    expect(names()).toEqual(['Hiddify']);
    expect(lineShown()).toBe(true);
  });

  test('a device-limited plan with no device-limit app left drops the empty heading', () => {
    props.modeId = 'freedom-xhttp';
    props.deviceLimited = true;
    // Karing was the only HWID app, and it can't use XHTTP.
    client.setQueryData(queryKeys.config, {
      clients: [
        app('Hiddify', 'hiddify', { xhttp: true, hwid: false }),
        app('Karing', 'karing', { xhttp: false, hwid: true }),
      ],
      backends: {
        list: [
          {
            id: 'remnawave',
            label: 'Remnawave',
            enabled: true,
            capabilities: { devices: true, accessKeyOnly: false, switchServer: true },
          },
        ],
      },
    });
    mounted = mountWithQuery(client, ConnectClient, props);
    flushSync();
    expect(names()).toEqual(['Hiddify']);
    expect(document.body.textContent).not.toContain('Works with your device limit');
    expect(document.body.textContent).toContain('Not recommended for your plan');
  });
});

describe('which apps a Hysteria mode offers', () => {
  const names = () =>
    [...document.querySelectorAll('ul > li')].map((li) =>
      li.querySelector('p')?.textContent?.trim(),
    );
  const text = () => document.body.textContent ?? '';

  test('only apps with Hysteria evidence; untested and false ones are left out, one line says why', () => {
    client.setQueryData(queryKeys.config, {
      clients: [
        app('Hiddify', 'hiddify', { hysteria2: false }),
        app('v2rayNG', 'v2rayng', { hysteria2: true }),
        // Untested: no flag. Unlike XHTTP, it is not offered.
        app('Shadowrocket', 'shadowrocket'),
      ],
      backends: { list: [] },
    });
    props.modeId = 'privacy-hysteria';
    mounted = mountWithQuery(client, ConnectClient, props);
    flushSync();
    expect(names()).toEqual(['v2rayNG']);
    expect(text()).toContain('Only apps we have checked with Hysteria are shown');
    expect(text()).not.toContain('use any compatible client');
  });

  test('none checked on this platform: it says to pick another mode, never "any compatible client"', () => {
    client.setQueryData(queryKeys.config, {
      clients: [
        app('Hiddify', 'hiddify', { hysteria2: false }),
        app('Shadowrocket', 'shadowrocket'),
      ],
      backends: { list: [] },
    });
    props.modeId = 'privacy-hysteria';
    mounted = mountWithQuery(client, ConnectClient, props);
    flushSync();
    expect(names()).toEqual([]);
    expect(text()).toContain('No app we have checked with Hysteria runs on this platform yet');
    expect(text()).not.toContain('use any compatible client');
    expect(text()).not.toContain('Only apps we have checked with Hysteria are shown');
  });

  test('the REALITY mode of the same family offers every app', () => {
    client.setQueryData(queryKeys.config, {
      clients: [
        app('Hiddify', 'hiddify', { hysteria2: false }),
        app('Shadowrocket', 'shadowrocket'),
      ],
      backends: { list: [] },
    });
    props.modeId = 'privacy-reality';
    mounted = mountWithQuery(client, ConnectClient, props);
    flushSync();
    expect(names()).toEqual(['Hiddify', 'Shadowrocket']);
  });
});
