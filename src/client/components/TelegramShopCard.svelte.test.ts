import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { queryKeys } from '@client/lib/queries';
import { mountWithQuery } from '../testing/mountWithQuery';
import TelegramShopCard from './TelegramShopCard.svelte';

let client: QueryClient;
let app: ReturnType<typeof mountWithQuery> | null = null;

beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
});
afterEach(() => {
  if (app) unmount(app);
  app = null;
  document.body.innerHTML = '';
  vi.unstubAllGlobals();
});

function show(telegram: { botUsername: string } | null, variant?: 'full' | 'compact') {
  client.setQueryData(queryKeys.config, { telegram });
  app = mountWithQuery(client, TelegramShopCard, variant ? { variant } : {});
  flushSync();
}
const text = () => document.body.textContent ?? '';
const hrefs = () => [...document.querySelectorAll('a')].map((a) => a.getAttribute('href'));

describe('TelegramShopCard', () => {
  test('renders nothing while the shop is closed', () => {
    show(null);
    expect(document.body.textContent?.trim()).toBe('');
  });

  test('the full card: the exact username, both links, the steps', () => {
    show({ botUsername: 'FreeSocksGiftBot' });
    expect(text()).toContain('Buy gift codes on Telegram');
    expect(text()).toContain('@FreeSocksGiftBot');
    expect(text()).toContain('Our only official bot');
    expect(text()).toContain('Redeem a code in FreeSocks');
    expect(hrefs()).toEqual([
      'tg://resolve?domain=FreeSocksGiftBot',
      'https://t.me/FreeSocksGiftBot',
    ]);
    // The web link opens apart from the site; no Stars prices on the site.
    const web = document.querySelector('a[href^="https://t.me/"]')!;
    expect(web.getAttribute('rel')).toBe('noopener noreferrer');
    expect(text()).not.toMatch(/\d+\s*Stars/);
    expect(text()).not.toContain('—');
  });

  test('the compact card keeps the username and links, without the steps', () => {
    show({ botUsername: 'FreeSocksGiftBot' }, 'compact');
    expect(text()).toContain('@FreeSocksGiftBot');
    expect(text()).not.toContain('How it works');
    expect(hrefs()).toHaveLength(2);
  });

  test('the copy button copies the @username', async () => {
    const writeText = vi.fn(async () => undefined);
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } });
    show({ botUsername: 'FreeSocksGiftBot' });
    (
      document.querySelector('button[aria-label="Copy the bot\'s username"]') as HTMLButtonElement
    ).click();
    await Promise.resolve();
    expect(writeText).toHaveBeenCalledWith('@FreeSocksGiftBot');
  });
});
