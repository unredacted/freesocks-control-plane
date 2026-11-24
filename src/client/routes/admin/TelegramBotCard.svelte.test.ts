import { QueryClient } from '@tanstack/svelte-query';
import { flushSync, tick, unmount } from 'svelte';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { mountWithQuery } from '../../testing/mountWithQuery';
import TelegramBotCard from './TelegramBotCard.svelte';

/** The Telegram gift shop card's Stars rate: shown, validated, saved. */
let view: Record<string, unknown> = {};
const patches: Record<string, unknown>[] = [];

vi.mock('@client/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@client/lib/api')>()),
  apiClient: {
    get: () => Promise.resolve(view),
    patch: (_path: string, body: Record<string, unknown>) => {
      patches.push(body);
      return Promise.resolve(view);
    },
    post: () => Promise.reject(new Error('no posts')),
  },
}));

const baseView = (starsValuePer1000: number | null) => ({
  enabled: true,
  botUsername: 'FreeSocksGiftBot',
  starsEnabled: true,
  starsPrices: [{ months: 3, stars: 700 }],
  starsValuePer1000,
  termsUrl: '',
  tokenSet: true,
  secretSet: true,
  webhookUrl: 'https://example.test/api/webhooks/telegram',
  webhook: null,
});

let app: ReturnType<typeof mountWithQuery> | null = null;

async function settle() {
  for (let i = 0; i < 8; i++) {
    await new Promise((r) => setTimeout(r, 0));
    await tick();
  }
  flushSync();
}

async function mount(currency: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  app = mountWithQuery(client, TelegramBotCard, { durations: [3, 12], currency });
  await settle();
}

const rateInput = () => document.querySelector('input[placeholder="13.00"]') as HTMLInputElement;
async function typeRate(value: string) {
  const input = rateInput();
  input.value = value;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  await settle();
}
async function save() {
  const button = [...document.querySelectorAll('button')].find(
    (b) => b.textContent?.trim() === 'Save Telegram shop',
  )!;
  button.click();
  await settle();
}
const text = () => (document.body.textContent ?? '').replace(/\s+/g, ' ');

afterEach(() => {
  patches.length = 0;
  if (app) unmount(app);
  app = null;
  document.body.innerHTML = '';
});

describe('TelegramBotCard Stars rate', () => {
  test('shows the rate in force and what a code is worth at it', async () => {
    view = baseView(1300);
    await mount('USD');
    expect(rateInput().value).toBe('13.00');
    expect(text()).toContain('$9.10 to you');
  });

  test('a cleared or non-numeric rate is refused, never dropped from the save', async () => {
    view = baseView(1300);
    await mount('USD');
    for (const bad of ['', 'abc', '0']) {
      await typeRate(bad);
      await save();
      expect(patches).toHaveLength(0);
    }
    await typeRate('14.50');
    await save();
    expect(patches).toHaveLength(1);
    expect(patches[0]).toMatchObject({ starsValuePer1000: 1450 });
  });

  test('outside USD with no rate yet: says so, and a blank field saves without one', async () => {
    view = baseView(null);
    await mount('EUR');
    expect(rateInput().value).toBe('');
    expect(text()).toContain('No rate in EUR yet');
    await save();
    expect(patches).toHaveLength(1);
    expect(patches[0]).not.toHaveProperty('starsValuePer1000');
  });
});
