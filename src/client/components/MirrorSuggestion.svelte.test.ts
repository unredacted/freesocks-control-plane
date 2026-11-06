import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, beforeAll, beforeEach, describe, expect, test, vi } from 'vitest';
import { apiClient } from '@client/lib/api';
import { queryKeys } from '@client/lib/queries';
import { mountWithQuery } from '../testing/mountWithQuery';
import MirrorSuggestion from './MirrorSuggestion.svelte';
import MirrorHelp from './MirrorHelp.svelte';

vi.mock('@client/lib/api', async (importOriginal) => {
  const real = await importOriginal<typeof import('@client/lib/api')>();
  return { ...real, apiClient: { ...real.apiClient, post: vi.fn() } };
});

const MAIN = 'https://site.example/api/v1/sub/token-1';
const A = 'https://cdn-1.example/mirrors/aaaa';

// jsdom has no Web Animations: Svelte's transitions finish at once.
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
let help: ReturnType<typeof mountWithQuery> | null = null;
const onPick = vi.fn();
const props = $state({
  mirrors: [] as string[],
  geoCountry: 'IR',
  subscriptionUrl: MAIN,
  link: MAIN,
  onPick,
});

beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  // MirrorHelp names apps from the catalog.
  client.setQueryData(queryKeys.config, { clients: [], backends: { list: [] } });
  props.mirrors = [];
  props.geoCountry = 'IR';
  props.link = MAIN;
  onPick.mockReset();
  vi.mocked(apiClient.post).mockReset();
});
afterEach(() => {
  if (app) unmount(app);
  if (help) unmount(help);
  app = null;
  help = null;
  client.clear();
});

const text = () => document.body.textContent ?? '';
const button = (label: string) =>
  [...document.querySelectorAll('button')].find((b) => b.textContent?.includes(label));
const radios = () => [...document.querySelectorAll<HTMLInputElement>('input[type="radio"]')];
const show = () => {
  app = mountWithQuery(client, MirrorSuggestion, props);
  flushSync();
};

describe('before a mirror exists', () => {
  test('says the main link may be blocked there and recommends a mirror link', () => {
    show();
    expect(text()).toContain('The main link may be blocked in Iran');
    expect(text()).toContain(
      'We recommend adding a mirror link to your app instead of the main link.',
    );
    // The country is prefilled in the picker.
    expect(document.getElementById('mirror-suggest-region')?.textContent).toContain('Iran');
    expect(radios()).toHaveLength(0);
  });

  test('creates nothing until the member clicks, then asks for the prefilled country', async () => {
    vi.mocked(apiClient.post).mockResolvedValue({
      status: 'ok',
      publicUrl: A,
      provider: 'p1',
      remaining: 2,
    });
    client.setQueryData(queryKeys.account, { subscription: { url: MAIN, mirrors: [] } });
    show();
    expect(apiClient.post).not.toHaveBeenCalled();

    button('Create a mirror link')!.click();
    await vi.waitFor(() => expect(onPick).toHaveBeenCalledWith(A));
    expect(apiClient.post).toHaveBeenCalledTimes(1);
    expect(vi.mocked(apiClient.post).mock.calls[0]!.slice(0, 2)).toEqual([
      '/api/v1/mirror/request',
      { countryCode: 'IR' },
    ]);
    // Written into the cached view at once (the pass and MirrorHelp read it).
    const cached = client.getQueryData<{ subscription: { mirrors: { publicUrl: string }[] } }>(
      queryKeys.account,
    );
    expect(cached?.subscription.mirrors.map((m) => m.publicUrl)).toEqual([A]);
  });

  test('a country not in the picker starts on Global', () => {
    props.geoCountry = 'ZZ';
    show();
    expect(document.getElementById('mirror-suggest-region')?.textContent).toContain(
      'Global (any region)',
    );
  });

  test('a refusal says why and picks nothing', async () => {
    vi.mocked(apiClient.post).mockResolvedValue({ status: 'exhausted', remaining: 1 });
    show();
    button('Create a mirror link')!.click();
    await vi.waitFor(() =>
      expect(text()).toContain('No more mirrors are available for your region right now.'),
    );
    expect(onPick).not.toHaveBeenCalled();
  });
});

describe('once the key has a mirror', () => {
  test('lists both links, the mirror recommended, and the current one checked', () => {
    props.mirrors = [A];
    props.link = A;
    show();
    expect(button('Create a mirror link')).toBeUndefined();
    expect(text()).toContain('Which link should your app use?');
    expect(text()).toContain(A);
    expect(text()).toContain(MAIN);
    const [mirror, main] = radios();
    expect(mirror!.value).toBe(A);
    expect(mirror!.checked).toBe(true);
    expect(mirror!.closest('label')?.textContent).toContain('Recommended');
    expect(main!.value).toBe(MAIN);
    expect(main!.checked).toBe(false);
    expect(main!.closest('label')?.textContent).not.toContain('Recommended');
  });

  test('picking the main link hands it to the parent', () => {
    props.mirrors = [A];
    props.link = A;
    show();
    radios()[1]!.click();
    expect(onPick).toHaveBeenCalledWith(MAIN);
    // The parent's answer is what shows as checked.
    props.link = MAIN;
    flushSync();
    expect(radios()[1]!.checked).toBe(true);
    expect(radios()[0]!.checked).toBe(false);
  });
});

describe('one mirror request at a time on the page', () => {
  // Both buttons on /get-account: two requests in flight for a key with no
  // mirror could race to the same provider.
  const both = () => {
    show();
    help = mountWithQuery(client, MirrorHelp, {
      mirrors: [],
      geoCountry: 'IR',
      subscriptionUrl: MAIN,
      available: true,
    });
    flushSync();
    button('Trouble connecting?')!.click();
    flushSync();
  };

  test("the suggestion's request holds MirrorHelp's button until it settles", async () => {
    let settle!: (v: unknown) => void;
    vi.mocked(apiClient.post).mockReturnValue(new Promise((r) => (settle = r)) as never);
    both();
    button('Create a mirror link')!.click();
    await vi.waitFor(() => expect(button('Get a mirror link')).toBeUndefined());
    // Both show the request running and neither can start another.
    const working = [...document.querySelectorAll('button')].filter((b) =>
      b.textContent?.includes('Working'),
    );
    expect(working).toHaveLength(2);
    expect(working.every((b) => b.disabled)).toBe(true);
    settle({ status: 'exhausted', remaining: 1 });
    await vi.waitFor(() => expect(button('Get a mirror link')?.disabled).toBe(false));
    expect(apiClient.post).toHaveBeenCalledTimes(1);
  });

  test("MirrorHelp's request holds the suggestion's button", async () => {
    vi.mocked(apiClient.post).mockReturnValue(new Promise(() => {}) as never);
    both();
    button('Get a mirror link')!.click();
    await vi.waitFor(() => expect(button('Create a mirror link')).toBeUndefined());
    expect(apiClient.post).toHaveBeenCalledTimes(1);
  });
});
