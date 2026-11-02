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
  linkListUrl?: string;
  modeId?: string;
  deviceLimited?: boolean;
}>({
  subscriptionUrl: MAIN,
});

beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(queryKeys.config, {
    clients: [app('Hiddify', 'hiddify'), app('sing-box', 'sing-box'), app('Clash', 'clash')],
    backends: { list: [] },
  });
  props.subscriptionUrl = MAIN;
  props.linkListUrl = undefined;
  props.modeId = undefined;
  props.deviceLimited = undefined;
});
afterEach(() => {
  if (mounted) unmount(mounted);
  mounted = null;
  client.clear();
});

/** Each app's "Open in" link and whether its card carries the main-link note. */
const cards = (): Record<string, { href: string | undefined; note: boolean }> =>
  Object.fromEntries(
    [...document.querySelectorAll('li')].map((li) => [
      li.querySelector('p')?.textContent?.trim() ?? '',
      {
        href: [...li.querySelectorAll('a')].find((a) => a.textContent?.includes('Open in'))?.href,
        note: li.textContent?.includes("this app can't read a mirror link") ?? false,
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

  test('a mirror picked: link-list apps import it, sing-box and Clash keep the main link', () => {
    props.linkListUrl = MIRROR;
    mounted = mountWithQuery(client, ConnectClient, props);
    flushSync();
    const c = cards();
    expect(c['Hiddify']!.href).toContain(MIRROR);
    expect(c['Hiddify']!.note).toBe(false);
    for (const name of ['sing-box', 'Clash']) {
      expect(c[name]!.href).toContain(encodeURIComponent(MAIN));
      expect(c[name]!.href).not.toContain(encodeURIComponent(MIRROR));
      expect(c[name]!.note).toBe(true);
    }
  });

  test('the main link picked: the same as no pick', () => {
    props.linkListUrl = MAIN;
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
