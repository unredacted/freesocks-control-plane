import { readFileSync } from 'node:fs';
import { describe, expect, test } from 'vitest';
import { buildBotMessagesSource, BOT_MESSAGES_PATH } from '../../../scripts/gen-bot-messages';
import { BOT_MESSAGES, BOT_MESSAGES_EN } from './botMessages.generated';
import {
  decodeAction,
  encodeAction,
  parseCommand,
  pickLocale,
  sellableDurations,
  shopOpen,
  starsOffer,
  tr,
  type Action,
  type ShopBilling,
} from './flow';
import { TELEGRAM_DEFAULTS, telegramConfigWrites, type TelegramConfig } from '../telegramConfig';

const REF = '0123456789abcdef0123456789abcdef';

describe('the button protocol', () => {
  const actions: Action[] = [
    { k: 'menu' },
    { k: 'langs' },
    { k: 'lang', lang: 'fa' },
    { k: 'privacy' },
    { k: 'buy' },
    { k: 'dur', months: 12 },
    { k: 'qty', months: 3, qty: 10 },
    { k: 'accept', months: 120, qty: 50 },
    { k: 'terms' },
    { k: 'ack', ref: REF },
  ];

  test('every action round-trips and fits in 64 bytes', () => {
    for (const a of actions) {
      const data = encodeAction('ru', a);
      expect(data.length).toBeLessThanOrEqual(64);
      const back = decodeAction(data);
      expect(back?.action).toEqual(a);
      expect(back?.lang).toBe(a.k === 'lang' ? a.lang : 'ru');
    }
  });

  test('anything off is refused', () => {
    for (const bad of [
      undefined,
      '',
      'x|en',
      'b|xx',
      'b|en|1',
      'd|en|0',
      'd|en|121',
      'q|en|3|51',
      't|en|3|1|x',
      'T|en|1',
      // The old crypto buttons no longer exist.
      'p|en|3|1|s',
      'c|en|3|1|usdttrc20',
      `k|en|${REF}`,
      `a|en|${REF.toUpperCase()}`,
      `a|en|${REF}|x`,
      'a|en|short',
      `b|en|${'x'.repeat(70)}`,
    ]) {
      expect(decodeAction(bad), String(bad)).toBeNull();
    }
  });

  test('commands', () => {
    expect(parseCommand('/buy')).toEqual({ name: 'buy' });
    expect(parseCommand('/paysupport')).toEqual({ name: 'paysupport' });
    expect(parseCommand('/start@FreeSocksShopBot buy')).toEqual({ name: 'start', arg: 'buy' });
    expect(parseCommand('hello')).toBeNull();
  });
});

describe('language and text', () => {
  test('picks the client language, else English', () => {
    expect(pickLocale('fa')).toBe('fa');
    expect(pickLocale('zh-hans')).toBe('zh');
    expect(pickLocale('ru-RU')).toBe('ru');
    expect(pickLocale('de')).toBe('en');
    expect(pickLocale(undefined)).toBe('en');
  });

  test('escapes every value put into HTML', () => {
    expect(tr('en', 'orderRef', { ref: '<b>&' })).toBe('Order &lt;b&gt;&amp;');
  });

  test('falls back to English until a translation lands', () => {
    expect(tr('fa', 'buttonBuy')).toBe(BOT_MESSAGES.fa.buttonBuy ?? BOT_MESSAGES_EN.buttonBuy);
  });

  test('the generated catalog matches messages/*.json', () => {
    expect(readFileSync(BOT_MESSAGES_PATH, 'utf8')).toBe(buildBotMessagesSource());
  });

  test('bot text uses no em dashes, and translations keep the same placeholders', () => {
    const holes = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
    for (const [key, en] of Object.entries(BOT_MESSAGES_EN)) {
      for (const [locale, msgs] of Object.entries(BOT_MESSAGES)) {
        const s = (msgs as Record<string, string>)[key];
        if (s === undefined) continue;
        expect(s, `${locale} bot.${key}`).not.toContain('—');
        expect(holes(s), `${locale} bot.${key}`).toEqual(holes(en));
      }
    }
  });
});

describe('what the shop sells', () => {
  const billing: ShopBilling = { enabled: true, durations: [{ months: 1 }, { months: 3 }] };
  const cfg = (over: Partial<TelegramConfig>): TelegramConfig => ({
    ...TELEGRAM_DEFAULTS,
    enabled: true,
    botUsername: 'FreeSocksShopBot',
    starsEnabled: true,
    starsPrices: [{ months: 3, stars: 700 }],
    ...over,
  });

  test('Stars only: a duration sells when it is in the catalog and has a Stars price', () => {
    expect(starsOffer(cfg({}), billing, 3)).toBe(700);
    expect(starsOffer(cfg({}), billing, 1)).toBeNull(); // no Stars price
    expect(starsOffer(cfg({ starsPrices: [{ months: 6, stars: 1 }] }), billing, 6)).toBeNull();
    expect(starsOffer(cfg({ starsEnabled: false }), billing, 3)).toBeNull();
    expect(starsOffer(cfg({}), { ...billing, enabled: false }, 3)).toBeNull();
    expect(sellableDurations(cfg({}), billing)).toEqual([3]);
  });

  test('the shop is open only with something to sell', () => {
    expect(shopOpen(cfg({}), billing)).toBe(true);
    expect(shopOpen(cfg({ enabled: false }), billing)).toBe(false);
    expect(shopOpen(cfg({ starsPrices: [] }), billing)).toBe(false);
    expect(shopOpen(cfg({}), { ...billing, enabled: false })).toBe(false);
  });
});

describe('admin settings validation', () => {
  test('accepts good values and refuses bad ones', () => {
    expect(telegramConfigWrites({ botUsername: '@FreeSocksShopBot', enabled: true })).toEqual([
      { key: 'telegram.enabled', value: true },
      { key: 'telegram.botUsername', value: 'FreeSocksShopBot' },
    ]);
    expect(telegramConfigWrites({ botUsername: '' })).toEqual([
      { key: 'telegram.botUsername', value: '' },
    ]);
    expect(() => telegramConfigWrites({ botUsername: 'a b' })).toThrow();
    expect(() => telegramConfigWrites({ starsPrices: [{ months: 3, stars: 0 }] })).toThrow();
    expect(() =>
      telegramConfigWrites({
        starsPrices: [
          { months: 3, stars: 10 },
          { months: 3, stars: 20 },
        ],
      }),
    ).toThrow();
  });
});
