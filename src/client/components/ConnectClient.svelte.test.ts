import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { queryKeys } from '@client/lib/queries';
import { mountWithQuery } from '../testing/mountWithQuery';
import ConnectClient from './ConnectClient.svelte';

const MAIN = 'https://site.example/api/v1/sub/token-1';
const MIRROR = 'https://cdn-1.example/mirrors/aaaa';
const ALL = ['android', 'ios', 'windows', 'desktop'];
const app = (name: string, schemeId: string | null) => ({
  name,
  platforms: ALL,
  backends: ['remnawave'],
  homepageUrl: `https://${name.toLowerCase()}.example`,
  schemeId,
  hwid: true,
  openSource: true,
});

let client: QueryClient;
let mounted: ReturnType<typeof mountWithQuery> | null = null;
const props = $state<{ subscriptionUrl: string; linkListUrl?: string }>({
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
