/// <reference types="vite/client" />
/**
 * The Telegram gift shop end to end: the webhook route (secret header, size
 * cap, dedupe), the Stars flow through the real billing core, the
 * shop and rail switches, and the privacy rule that no table keeps the chat.
 * Telegram's Bot API is a fetch stub.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { api, internal } from './_generated/api';

const modules = import.meta.glob('./**/*.*s');
const TOKEN = '123456789:SECRET_bot_token_abcdefghijklmnopqrstuv';
const SECRET = 'hook-secret_123';
const CHAT = 918273645;

type Call = { method: string; body: Record<string, unknown>; url: string };

/** What the stubbed Telegram says about the bot and its webhook (tests change it). */
const tgState = { username: 'FreeSocksShopBot', pending: 0, hookUrl: '' };
beforeEach(() => {
  tgState.username = 'FreeSocksShopBot';
  tgState.pending = 0;
  tgState.hookUrl = '';
});

/** `fail`: Bot API methods that fail once (Telegram answers an error). */
function stubFetch(fail: string[] = []) {
  const calls: Call[] = [];
  const failing = [...fail];
  let nextMessageId = 500;
  const fn = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const u = String(url);
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
    if (u.startsWith('https://api.telegram.org/')) {
      const method = u.split('/').pop()!;
      calls.push({ method, body, url: u });
      const f = failing.indexOf(method);
      if (f >= 0) {
        failing.splice(f, 1);
        return Response.json(
          { ok: false, error_code: 502, description: 'Bad Gateway' },
          { status: 502 },
        );
      }
      if (method === 'setWebhook') tgState.hookUrl = String(body.url);
      if (method === 'deleteWebhook') tgState.hookUrl = '';
      const result =
        method === 'sendMessage'
          ? { message_id: nextMessageId++ }
          : method === 'getMe'
            ? { id: 1, username: tgState.username }
            : method === 'getWebhookInfo'
              ? { url: tgState.hookUrl, pending_update_count: tgState.pending }
              : true;
      return Response.json({ ok: true, result });
    }
    throw new Error(`unexpected fetch ${u}`);
  });
  vi.stubGlobal('fetch', fn);
  return { calls, sent: (m: string) => calls.filter((c) => c.method === m) };
}

async function seed(
  t: ReturnType<typeof convexTest>,
  opts: { shop?: boolean; stars?: boolean } = {},
) {
  await t.run(async (ctx) => {
    const base = {
      backend: 'remnawave' as const,
      deviceLimit: 0,
      hwidLimit: 0,
      hwidEnabled: false,
      isActive: true,
      expirationDaysAfterMembershipLapse: 0,
      updatedAt: Date.now(),
    };
    await ctx.db.insert('tiers', {
      ...base,
      slug: 'member',
      name: 'FreeSocks Membership',
      monthlyTrafficGb: 0,
      trafficStrategy: 'NO_RESET',
      isDefaultFree: false,
      priority: 10,
    });
    const put = (key: string, value: unknown) =>
      ctx.db.insert('appSettings', { key, value: JSON.stringify(value), updatedAt: Date.now() });
    await put('billing.enabled', true);
    await put('billing.nowpayments.enabled', true);
    await put('billing.membership.durations', [
      { months: 3, amountCents: 1400 },
      { months: 12, amountCents: 5000 },
    ]);
    await put('telegram.enabled', opts.shop ?? true);
    await put('telegram.botUsername', 'FreeSocksShopBot');
    await put('telegram.stars.enabled', opts.stars ?? true);
    await put('telegram.stars.prices', [{ months: 3, stars: 700 }]);
  });
}

let nextUpdate = 1;
function message(text: string, extra: Record<string, unknown> = {}) {
  const id = nextUpdate++;
  return {
    update_id: id,
    message: {
      message_id: id,
      chat: { id: CHAT, type: 'private' },
      from: { id: CHAT, language_code: 'en' },
      text,
      ...extra,
    },
  };
}
function button(data: string, messageId = 50) {
  const id = nextUpdate++;
  return {
    update_id: id,
    callback_query: {
      id: `cq${id}`,
      from: { id: CHAT, language_code: 'en' },
      data,
      message: { message_id: messageId, chat: { id: CHAT, type: 'private' } },
    },
  };
}

function post(t: ReturnType<typeof convexTest>, update: unknown, secret: string | null = SECRET) {
  return t.fetch('/api/webhooks/telegram', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(secret !== null ? { 'x-telegram-bot-api-secret-token': secret } : {}),
    },
    body: JSON.stringify(update),
  });
}

beforeEach(() => {
  vi.stubEnv('TELEGRAM_BOT_TOKEN', TOKEN);
  vi.stubEnv('TELEGRAM_WEBHOOK_SECRET', SECRET);
  vi.stubEnv('IP_HASH_SALT', 'salt');
  vi.stubEnv('PUBLIC_BASE_URL', 'https://beta.freesocks.example');
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe('the webhook route', () => {
  test('answers 503 while the secret is unset', async () => {
    vi.stubEnv('TELEGRAM_WEBHOOK_SECRET', '');
    const t = convexTest(schema, modules);
    const res = await post(t, message('/start'));
    expect(res.status).toBe(503);
  });

  test('refuses a missing or wrong secret, and runs nothing', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { calls } = stubFetch();
    expect((await post(t, message('/start'), null)).status).toBe(401);
    expect((await post(t, message('/start'), 'wrong')).status).toBe(401);
    expect(calls).toHaveLength(0);
    await t.run(async (ctx) => {
      expect(await ctx.db.query('telegramUpdates').collect()).toHaveLength(0);
    });
  });

  test('refuses an oversized body', async () => {
    const t = convexTest(schema, modules);
    const res = await post(t, { update_id: 1, message: { text: 'x'.repeat(70_000) } });
    expect(res.status).toBe(413);
  });

  test('handles a redelivered update once', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { sent } = stubFetch();
    const update = message('/start');
    expect((await post(t, update)).status).toBe(200);
    expect((await post(t, update)).status).toBe(200);
    expect(sent('sendMessage')).toHaveLength(1);
  });

  test('ignores group chats (codes must never be shown to a group)', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { calls } = stubFetch();
    const update = message('/buy');
    (update.message.chat as { type: string }).type = 'group';
    expect((await post(t, update)).status).toBe(200);
    expect(calls).toHaveLength(0);
  });
});

describe('the shop', () => {
  test('closed: says so and creates nothing', async () => {
    const t = convexTest(schema, modules);
    await seed(t, { shop: false });
    const { sent } = stubFetch();
    await post(t, message('/buy'));
    await post(t, button('t|en|3|1|700'));
    expect(String(sent('sendMessage')[0]?.body.text)).toMatch(/closed/);
    await t.run(async (ctx) => {
      expect(await ctx.db.query('billingOrders').collect()).toHaveLength(0);
    });
  });

  test('walks start, duration, quantity, terms, then the Stars invoice', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { sent, calls } = stubFetch();
    await post(t, message('/start'));
    expect(String(sent('sendMessage')[0]?.body.text)).toMatch(/gift codes/);
    await post(t, button('b|en'));
    const durations = calls.at(-1)!;
    expect(durations.method).toBe('editMessageText');
    // 3 and 12 months are in the catalog; only 3 has a Stars price.
    const kb = (durations.body.reply_markup as { inline_keyboard: { text: string }[][] })
      .inline_keyboard;
    expect(kb.flat().map((b) => b.text)).toEqual(['3 months', 'Back']);
    await post(t, button('q|en|3|2'));
    // The terms and the price come first; the invoice only after Accept.
    const terms = calls.at(-1)!;
    expect(String(terms.body.text)).toMatch(/Price: 1400 Stars/);
    expect(String(terms.body.text)).toMatch(/Terms of sale/);
    const termsKb = (
      terms.body.reply_markup as { inline_keyboard: { text: string }[][] }
    ).inline_keyboard.flat();
    expect(termsKb.map((b) => b.text)).toEqual(['I accept, pay 1400 Stars', 'Back']);
    expect(sent('sendInvoice')).toHaveLength(0);
    await post(t, button('t|en|3|2|700'));
    expect(sent('sendInvoice')[0]!.body.prices).toEqual([{ label: 'Gift codes', amount: 1400 }]);
  });

  test('a forged button is ignored', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { sent, calls } = stubFetch();
    await post(t, button('t|en|3|999'));
    await post(t, button('p|en|3|1|n')); // the old crypto button
    expect(calls.map((c) => c.method)).toEqual(['answerCallbackQuery', 'answerCallbackQuery']);
    expect(sent('sendMessage')).toHaveLength(0);
  });
});

describe('Telegram Stars', () => {
  test('invoice, pre-checkout, payment, codes: exactly once', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { sent } = stubFetch();
    await post(t, button('t|en|3|2|700'));
    const invoice = sent('sendInvoice')[0]!.body;
    expect(invoice.currency).toBe('XTR');
    expect(invoice.provider_token).toBe('');
    // Single-chat: a forwarded copy cannot be paid by someone else.
    expect(invoice.start_parameter).toBe('buy');
    expect(invoice.prices).toEqual([{ label: 'Gift codes', amount: 1400 }]);
    const ref = String(invoice.payload);
    expect(ref).toMatch(/^[0-9a-f]{32}$/);

    const pre = (amount: number) => ({
      update_id: nextUpdate++,
      pre_checkout_query: {
        id: `pq${nextUpdate}`,
        from: { id: CHAT, language_code: 'en' },
        currency: 'XTR',
        total_amount: amount,
        invoice_payload: ref,
      },
    });
    await post(t, pre(1));
    await post(t, pre(1400));
    expect(sent('answerPreCheckoutQuery').map((c) => c.body.ok)).toEqual([false, true]);

    const payment = (chargeId: string) =>
      message('', {
        text: undefined,
        successful_payment: {
          currency: 'XTR',
          total_amount: 1400,
          invoice_payload: ref,
          telegram_payment_charge_id: chargeId,
        },
      });
    const first = payment('charge_1');
    await post(t, first);
    await post(t, first); // Telegram redelivers the same update
    await post(t, payment('charge_1')); // or the same payment in a new update
    const codesMessages = sent('sendMessage').filter((c) => String(c.body.text).includes('FSM-'));
    expect(codesMessages).toHaveLength(1);
    expect(String(codesMessages[0]!.body.text).match(/FSM-[0-9A-Z-]+/g)).toHaveLength(2);
    await t.run(async (ctx) => {
      expect(await ctx.db.query('redemptionCodes').collect()).toHaveLength(2);
    });
  });

  async function starsOrder(t: ReturnType<typeof convexTest>, sent: (m: string) => Call[]) {
    await post(t, button('t|en|3|1|700'));
    return String(sent('sendInvoice').at(-1)!.body.payload);
  }
  const starsPaid = (ref: string, chargeId: string, refunded = false) =>
    message('', {
      text: undefined,
      [refunded ? 'refunded_payment' : 'successful_payment']: {
        currency: 'XTR',
        total_amount: 700,
        invoice_payload: ref,
        telegram_payment_charge_id: chargeId,
      },
    });

  test('a second payment on a paid order is refunded and leaves the order alone', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { sent } = stubFetch();
    const ref = await starsOrder(t, sent);
    await post(t, starsPaid(ref, 'charge_a'));
    await post(t, starsPaid(ref, 'charge_b'));
    expect(sent('refundStarPayment').map((c) => c.body)).toEqual([
      { user_id: CHAT, telegram_payment_charge_id: 'charge_b' },
    ]);
    expect(String(sent('sendMessage').at(-1)!.body.text)).toMatch(/refunded in full/);
    // Telegram then reports that refund: it is not this order's refund.
    await post(t, starsPaid(ref, 'charge_b', true));
    await t.run(async (ctx) => {
      const actions = (await ctx.db.query('auditLog').collect()).map((a) => a.action);
      expect(actions).toContain('billing.overpayment_seen');
      expect(actions).not.toContain('billing.refund_seen');
      expect(await ctx.db.query('redemptionCodes').collect()).toHaveLength(1);
    });
  });

  test('codes are sent again when Telegram refused them the first time', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { sent } = stubFetch(['sendMessage']);
    const ref = await starsOrder(t, sent);
    const update = starsPaid(ref, 'charge_r');
    expect((await post(t, update)).status).toBe(500);
    expect((await post(t, update)).status).toBe(200); // Telegram redelivers it
    const codes = sent('sendMessage').filter((c) => String(c.body.text).includes('FSM-'));
    expect(codes).toHaveLength(2); // the refused one, then the delivered one
    await t.run(async (ctx) => {
      expect(await ctx.db.query('redemptionCodes').collect()).toHaveLength(1);
    });
  });

  test('a refund Telegram refuses for a moment is retried on redelivery', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { sent } = stubFetch(['refundStarPayment']);
    const ref = await starsOrder(t, sent);
    await post(t, starsPaid(ref, 'charge_a'));
    const second = starsPaid(ref, 'charge_b');
    expect((await post(t, second)).status).toBe(500);
    expect((await post(t, second)).status).toBe(200); // Telegram redelivers it
    expect(sent('refundStarPayment')).toHaveLength(2);
    expect(String(sent('sendMessage').at(-1)!.body.text)).toMatch(/refunded in full/);
    // A third delivery of the same payment refunds nothing more.
    await post(t, starsPaid(ref, 'charge_b'));
    expect(sent('refundStarPayment')).toHaveLength(2);
  });

  test('a price changed after the terms were shown is never charged', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { sent, calls } = stubFetch();
    // The buyer saw 600 per code; the price is now 700.
    await post(t, button('t|en|3|1|600'));
    expect(sent('sendInvoice')).toHaveLength(0);
    expect(String(calls.at(-1)!.body.text)).toMatch(/The price changed/);
    expect(JSON.stringify(calls.at(-1)!.body.reply_markup)).toContain('t|en|3|1|700');
    await t.run(async (ctx) => {
      expect(await ctx.db.query('billingOrders').collect()).toHaveLength(0);
    });
  });
});

describe('terms and support', () => {
  test('/terms, /paysupport and /support answer even while closed', async () => {
    const t = convexTest(schema, modules);
    await seed(t, { shop: false });
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'site.supportEmail',
        value: JSON.stringify('help@freesocks.example'),
        updatedAt: Date.now(),
      }),
    );
    const { sent } = stubFetch();
    await post(t, message('/terms'));
    expect(String(sent('sendMessage').at(-1)!.body.text)).toMatch(/Terms of sale/);
    await post(t, message('/paysupport'));
    expect(String(sent('sendMessage').at(-1)!.body.text)).toMatch(/help@freesocks\.example/);
    await post(t, message('/support'));
    expect(String(sent('sendMessage').at(-1)!.body.text)).toMatch(/@BotSupport cannot help/);
  });

  test('register keeps pending updates and lists /terms and /paysupport', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { sent } = stubFetch();
    await t.action(internal.telegramAdmin.setWebhook, { action: 'register' });
    expect(sent('setWebhook')[0]!.body).not.toHaveProperty('drop_pending_updates');
    const commands = (sent('setMyCommands')[0]!.body.commands as { command: string }[]).map(
      (c) => c.command,
    );
    expect(commands).toEqual(['buy', 'terms', 'paysupport', 'language', 'privacy', 'help']);
    await t.action(internal.telegramAdmin.setWebhook, { action: 'remove' });
    expect(sent('deleteWebhook')[0]!.body).toEqual({ drop_pending_updates: false });
  });
});

describe('the public link', () => {
  test('only while the bot would answer as open', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    stubFetch();
    const link = async () => (await t.query(api.publicConfig.get, {})).telegram;
    // Open, but the webhook was never registered: nobody would answer.
    expect(await link()).toBeNull();
    await t.action(internal.telegramAdmin.setWebhook, { action: 'register' });
    expect(await link()).toEqual({ botUsername: 'FreeSocksShopBot' });
    // Nothing to sell: the bot says closed, the site stays quiet.
    await t.mutation(internal.telegramAdmin.setConfig, { starsEnabled: false });
    expect(await link()).toBeNull();
    await t.mutation(internal.telegramAdmin.setConfig, { starsEnabled: true });
    expect(await link()).not.toBeNull();
    // The configured name changes away from the token's own: hidden.
    await t.mutation(internal.telegramAdmin.setConfig, { botUsername: 'SomeoneElsesBot' });
    expect(await link()).toBeNull();
    await t.mutation(internal.telegramAdmin.setConfig, { botUsername: 'FreeSocksShopBot' });
    expect(await link()).not.toBeNull();
    // Remove keeps the secret but stops Telegram calling us.
    await t.action(internal.telegramAdmin.setWebhook, { action: 'remove' });
    expect(await link()).toBeNull();
    // A new token for another bot, not registered yet.
    await t.mutation(internal.telegramAdmin.setConfig, {
      botToken: '222222222:ANOTHER_bot_token_abcdefghijklmnopqrst',
    });
    expect(await link()).toBeNull();
    await t.action(internal.telegramAdmin.setWebhook, { action: 'register' });
    expect(await link()).toEqual({ botUsername: 'FreeSocksShopBot' });
  });
});

describe('changing bots safely', () => {
  test('register refuses a username the token does not belong to', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    stubFetch();
    tgState.username = 'AnImpostorBot';
    await expect(
      t.action(internal.telegramAdmin.setWebhook, { action: 'register' }),
    ).rejects.toThrow(/belongs to @AnImpostorBot, not @FreeSocksShopBot/);
    expect((await t.query(api.publicConfig.get, {})).telegram).toBeNull();
  });

  test("another bot's token waits until the current webhook is removed", async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    stubFetch();
    await t.action(internal.telegramAdmin.setWebhook, { action: 'register' });
    const other = '222222222:ANOTHER_bot_token_abcdefghijklmnopqrst';
    await expect(t.mutation(internal.telegramAdmin.setConfig, { botToken: other })).rejects.toThrow(
      /different bot/,
    );
    // A new token for the SAME bot (a rotation) is fine.
    await t.mutation(internal.telegramAdmin.setConfig, {
      botToken: '123456789:ROTATED_token_abcdefghijklmnopqrstuv',
    });
    await t.action(internal.telegramAdmin.setWebhook, { action: 'remove' });
    await t.mutation(internal.telegramAdmin.setConfig, { botToken: other });
  });

  test('remove waits while Telegram still holds updates (they may be payments)', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { sent } = stubFetch();
    await t.action(internal.telegramAdmin.setWebhook, { action: 'register' });
    tgState.pending = 3;
    await expect(t.action(internal.telegramAdmin.setWebhook, { action: 'remove' })).rejects.toThrow(
      /3 updates waiting/,
    );
    expect(sent('deleteWebhook')).toHaveLength(0);
    tgState.pending = 0;
    await t.action(internal.telegramAdmin.setWebhook, { action: 'remove' });
    expect(sent('deleteWebhook')).toHaveLength(1);
  });
});

describe('the codes message', () => {
  test('saved-and-deleted, then gone; nothing keeps the chat', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { sent } = stubFetch();
    await post(t, button('t|en|3|1|700'));
    const ref = String(sent('sendInvoice').at(-1)!.body.payload);
    await post(
      t,
      message('', {
        text: undefined,
        successful_payment: {
          currency: 'XTR',
          total_amount: 700,
          invoice_payload: ref,
          telegram_payment_charge_id: 'charge_saved',
        },
      }),
    );
    const codes = sent('sendMessage').at(-1)!;
    expect(String(codes.body.text)).toMatch(/FSM-/);
    const saved = (codes.body.reply_markup as { inline_keyboard: { callback_data?: string }[][] })
      .inline_keyboard[0]![0]!.callback_data!;
    expect(saved).toBe(`a|en|${ref}`);

    await post(t, button(saved, 777));
    expect(sent('deleteMessage').at(-1)!.body).toEqual({ chat_id: CHAT, message_id: 777 });
    expect(String(sent('sendMessage').at(-1)!.body.text)).toMatch(/^Deleted/);
    const status = await t.query(internal.billing.botOrderStatus, { orderRef: ref });
    expect(status?.giftCodes).toEqual([]);

    // Privacy: no table holds the chat id (the rate-limit subject is a salted HMAC).
    await t.run(async (ctx) => {
      for (const table of Object.keys(schema.tables)) {
        const rows = await ctx.db.query(table as 'users').collect();
        expect(JSON.stringify(rows), table).not.toContain(String(CHAT));
      }
    });
  });

  test('a delete Telegram refuses for a moment keeps the codes for another try', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { sent } = stubFetch(['deleteMessage']);
    await post(t, button('t|en|3|1|700'));
    const ref = String(sent('sendInvoice').at(-1)!.body.payload);
    await post(
      t,
      message('', {
        text: undefined,
        successful_payment: {
          currency: 'XTR',
          total_amount: 700,
          invoice_payload: ref,
          telegram_payment_charge_id: 'charge_del',
        },
      }),
    );
    await post(t, button(`a|en|${ref}`, 901));
    expect(String(sent('sendMessage').at(-1)!.body.text)).toMatch(/could not delete/);
    expect(
      (await t.query(internal.billing.botOrderStatus, { orderRef: ref }))?.giftCodes,
    ).toHaveLength(1);
    await post(t, button(`a|en|${ref}`, 901));
    expect(String(sent('sendMessage').at(-1)!.body.text)).toMatch(/^Deleted/);
    expect((await t.query(internal.billing.botOrderStatus, { orderRef: ref }))?.giftCodes).toEqual(
      [],
    );
  });

  test('per-chat checkout limit', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { sent } = stubFetch();
    for (let i = 0; i < 7; i++) await post(t, button('t|en|3|1|700'));
    expect(String(sent('sendMessage').at(-1)!.body.text)).toMatch(/Too many requests/);
    await t.run(async (ctx) => {
      expect(await ctx.db.query('billingOrders').collect()).toHaveLength(6);
    });
  });
});

describe('update retention', () => {
  test('drops update ids after two days', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.telegramBot.claimUpdate, { updateId: 1 });
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 3 * 86_400_000);
    const res = await t.mutation(internal.telegramBot.sweepUpdates, {});
    vi.useRealTimers();
    expect(res.removed).toBe(1);
  });

  test('keeps draining a large backlog, whatever the page count', async () => {
    const t = convexTest(schema, modules);
    vi.useFakeTimers();
    await t.run(async (ctx) => {
      for (let i = 0; i < 1001; i++) await ctx.db.insert('telegramUpdates', { updateId: i });
    });
    vi.setSystemTime(Date.now() + 3 * 86_400_000);
    // Deep into a long drain (the old cap stopped at 50 rounds).
    await t.mutation(internal.telegramBot.sweepUpdates, { rounds: 99 });
    await t.finishAllScheduledFunctions(vi.runAllTimers);
    vi.useRealTimers();
    await t.run(async (ctx) => {
      expect(await ctx.db.query('telegramUpdates').collect()).toHaveLength(0);
    });
  });
});

describe('credentials saved from the admin card', () => {
  const SAVED = '987654321:SAVED_token_from_admin_card_abcdefghij';

  test('the token is write-only: saved, audited as a boolean, never shown', async () => {
    vi.stubEnv('TELEGRAM_BOT_TOKEN', '');
    const t = convexTest(schema, modules);
    await seed(t);
    expect((await t.query(internal.telegramAdmin.view, {})).tokenSet).toBe(false);
    await t.mutation(internal.telegramAdmin.setConfig, { botToken: ` ${SAVED} ` });
    const view = await t.query(internal.telegramAdmin.view, {});
    expect(view.tokenSet).toBe(true);
    expect(JSON.stringify(view)).not.toContain('SAVED_token');
    // A blank token leaves the saved one alone; a malformed one is refused.
    await t.mutation(internal.telegramAdmin.setConfig, { botToken: '', enabled: true });
    expect((await t.query(internal.telegramAdmin.secrets, {})).botToken).toBe(SAVED);
    await expect(
      t.mutation(internal.telegramAdmin.setConfig, { botToken: 'not-a-token' }),
    ).rejects.toThrow(/BotFather/);
    await t.run(async (ctx) => {
      const audits = await ctx.db.query('auditLog').collect();
      const changes = audits.filter((a) => a.action === 'admin.telegram.change');
      expect(changes.map((a) => (a.payload as { tokenChanged?: boolean }).tokenChanged)).toEqual([
        true,
        false,
      ]);
      expect(JSON.stringify(audits)).not.toContain('SAVED_token');
    });
  });

  test('a saved token wins over the env fallback', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    await t.mutation(internal.telegramAdmin.setConfig, { botToken: SAVED });
    const { calls } = stubFetch();
    expect((await post(t, message('/start'))).status).toBe(200);
    expect(calls.length).toBeGreaterThan(0);
    for (const c of calls) expect(c.url).toContain(`/bot${SAVED}/`);
  });

  test('register makes, saves and reuses the webhook secret', async () => {
    vi.stubEnv('TELEGRAM_WEBHOOK_SECRET', '');
    const t = convexTest(schema, modules);
    await seed(t);
    expect((await t.query(internal.telegramAdmin.view, {})).secretSet).toBe(false);
    expect((await post(t, message('/start'), 'anything')).status).toBe(503);

    const { sent } = stubFetch();
    await t.action(internal.telegramAdmin.setWebhook, { action: 'register' });
    const made = (await t.query(internal.telegramAdmin.secrets, {})).webhookSecret;
    expect(made).toMatch(/^[0-9a-f]{64}$/);
    expect(sent('setWebhook')[0]!.body.secret_token).toBe(made);
    expect((await t.query(internal.telegramAdmin.view, {})).secretSet).toBe(true);

    // Telegram's deliveries now carry it; anything else is refused.
    expect((await post(t, message('/start'), made)).status).toBe(200);
    expect((await post(t, message('/start'), SECRET)).status).toBe(401);

    // Registering again keeps the same secret.
    await t.action(internal.telegramAdmin.setWebhook, { action: 'register' });
    expect(sent('setWebhook')[1]!.body.secret_token).toBe(made);
    await t.run(async (ctx) => {
      expect(JSON.stringify(await ctx.db.query('auditLog').collect())).not.toContain(made);
    });
  });
});
