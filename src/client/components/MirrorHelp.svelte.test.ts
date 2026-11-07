import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, beforeAll, beforeEach, describe, expect, test, vi } from 'vitest';
import { apiClient } from '@client/lib/api';
import { queryKeys } from '@client/lib/queries';
import { mountWithQuery } from '../testing/mountWithQuery';
import MirrorHelp from './MirrorHelp.svelte';

vi.mock('@client/lib/api', async (importOriginal) => {
  const real = await importOriginal<typeof import('@client/lib/api')>();
  return { ...real, apiClient: { ...real.apiClient, post: vi.fn(), delete: vi.fn() } };
});

const A = { provider: 'p1', publicUrl: 'https://cdn-1.example/mirrors/aaaa' };
const B = { provider: 'p2', publicUrl: 'https://cdn-2.example/mirrors/aaaa' };

// jsdom has no Web Animations: Svelte's slide/fade transitions finish at once.
beforeAll(() => {
  Element.prototype.animate ??= function () {
    const animation = {
      onfinish: null as null | (() => void),
      cancel() {},
      finished: Promise.resolve(),
      currentTime: 0,
    };
    setTimeout(() => animation.onfinish?.(), 0);
    return animation as unknown as Animation;
  };
});

let client: QueryClient;
let app: ReturnType<typeof mountWithQuery> | null = null;
const props = $state({
  mirrors: [A] as { provider: string; publicUrl: string; formats?: string[] }[],
  subscriptionUrl: 'https://site.example/api/v1/sub/token-1',
  available: true,
});

/** The catalog the labels name apps from (src/shared/mirrorFormats.ts formats). */
const CATALOG = {
  clients: [
    { name: 'Hiddify', format: 'links' },
    { name: 'Clash', format: 'clash' },
    { name: 'FlClash', format: 'clash' },
    { name: 'sing-box', format: 'singbox' },
  ],
  backends: { list: [] },
};

beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(queryKeys.config, CATALOG);
  props.mirrors = [A];
  props.subscriptionUrl = 'https://site.example/api/v1/sub/token-1';
  vi.mocked(apiClient.post).mockReset();
  vi.mocked(apiClient.delete).mockReset();
});
afterEach(() => {
  if (app) unmount(app);
  app = null;
  client.clear();
});

const text = () => document.body.textContent ?? '';
const button = (label: string) =>
  [...document.querySelectorAll('button')].find((b) => b.textContent?.includes(label))!;
const show = () => {
  app = mountWithQuery(client, MirrorHelp, props);
  flushSync();
  button('Trouble connecting?').click();
  flushSync();
};

describe("the member's mirror list follows the server", () => {
  test('a mirror the server stops listing (withdrawn, or its refresh failed) leaves the list', () => {
    show();
    expect(text()).toContain(A.publicUrl);
    props.mirrors = [];
    flushSync();
    expect(text()).not.toContain(A.publicUrl);
  });

  test('a mirror just added shows at once, and a later withdrawal still removes it', async () => {
    vi.mocked(apiClient.post).mockResolvedValue({
      status: 'ok',
      publicUrl: B.publicUrl,
      provider: B.provider,
      remaining: 1,
    });
    show();
    button('Try another mirror').click();
    await vi.waitFor(() => expect(text()).toContain(B.publicUrl));
    // The refetch lists it, then its provider is removed: gone, not back.
    props.mirrors = [A, B];
    flushSync();
    props.mirrors = [A];
    flushSync();
    expect(text()).toContain(A.publicUrl);
    expect(text()).not.toContain(B.publicUrl);
  });

  test('removing all clears the cached view too (the onboarding pick follows it)', async () => {
    vi.mocked(apiClient.delete).mockResolvedValue({ removed: 1 });
    client.setQueryData(queryKeys.account, { subscription: { url: 'x', mirrors: [A] } });
    show();
    button('Remove all mirrors').click();
    await vi.waitFor(() =>
      expect(
        client.getQueryData<{ subscription: { mirrors: unknown[] } }>(queryKeys.account)
          ?.subscription.mirrors,
      ).toEqual([]),
    );
  });

  test('removing all hides them before the refetch; a new key starts clean', async () => {
    vi.mocked(apiClient.delete).mockResolvedValue({ removed: 1 });
    show();
    button('Remove all mirrors').click();
    await vi.waitFor(() => expect(text()).not.toContain(A.publicUrl));
    props.mirrors = [];
    flushSync();
    // A new key carrying a mirror (a mode switch carries them): shown.
    props.subscriptionUrl = 'https://site.example/api/v1/sub/token-2';
    props.mirrors = [B];
    flushSync();
    expect(text()).toContain(B.publicUrl);
  });
});

describe('each mirror is listed in every format it holds', () => {
  const codes = () => [...document.querySelectorAll('code')].map((c) => c.textContent?.trim());

  test('a link per format, each labelled with the apps that read it', () => {
    props.mirrors = [{ ...A, formats: ['links', 'clash', 'singbox'] }];
    show();
    expect(codes()).toEqual([A.publicUrl, `${A.publicUrl}.yaml`, `${A.publicUrl}.json`]);
    expect(text()).toContain('For most apps');
    expect(text()).toContain('For Clash and FlClash');
    expect(text()).toContain('For sing-box');
    expect(text()).toContain('Add the link for your app');
  });

  test('a mirror from before formats: its one link, until its next upload', () => {
    show();
    expect(codes()).toEqual([A.publicUrl]);
  });

  test('a format no catalog app reads is not offered', () => {
    client.setQueryData(queryKeys.config, {
      ...CATALOG,
      clients: CATALOG.clients.filter((c) => c.format !== 'singbox'),
    });
    props.mirrors = [{ ...A, formats: ['links', 'clash', 'singbox'] }];
    show();
    expect(codes()).toEqual([A.publicUrl, `${A.publicUrl}.yaml`]);
  });
});
