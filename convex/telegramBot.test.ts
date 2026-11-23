/// <reference types="vite/client" />
/**
 * The Telegram gift shop end to end: the webhook route (secret header, size
 * cap, dedupe), the Stars and crypto flows through the real billing core, the
 * shop and rail switches, and the privacy rule that no table keeps the chat.
 * Telegram's Bot API and NOWPayments are a fetch stub.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { hmacSha512Hex } from './lib/crypto';

const modules = import.meta.glob('./**/*.*s');
const TOKEN = '123456789:SECRET_bot_token_abcdefghijklmnopqrstuv';
const SECRET = 'hook-secret_123';
const CHAT = 918273645;
const IPN_SECRET = 'test-ipn-secret';

type Call = { method: string; body: Record<string, unknown>; url: string };

function stubFetch() {
  const calls: Call[] = [];
  let nextMessageId = 500;
  const fn = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const u = String(url);
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
    if (u.startsWith('https://api.telegram.org/')) {
      const method = u.split('/').pop()!;
      calls.push({ method, body, url: u });
      const result =
        method === 'sendMessage'
          ? { message_id: nextMessageId++ }
          : method === 'getMe'
            ? { id: 1, username: 'FreeSocksShopBot' }
            : true;
      return Response.json({ ok: true, result });
    }
    if (u.includes('nowpayments') && u.endsWith('/v1/invoice')) {
      return Response.json({ id: 'inv_tg', invoice_url: 'https://pay.example/i/inv_tg' });
    }
    throw new Error(`unexpected fetch ${u}`);
  });
  vi.stubGlobal('fetch', fn);
  return { calls, sent: (m: string) => calls.filter((c) => c.method === m) };
}

async function seed(
  t: ReturnType<typeof convexTest>,
  opts: { shop?: boolean; stars?: boolean; crypto?: boolean } = {},
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
    await put('telegram.crypto.enabled', opts.crypto ?? true);
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
  vi.stubEnv('NOWPAYMENTS_API_KEY', 'np-key');
  vi.stubEnv('NOWPAYMENTS_IPN_SECRET', IPN_SECRET);
  vi.stubEnv('NOWPAYMENTS_API_URL', 'https://api-sandbox.nowpayments.io');
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
    await post(t, button('p|en|3|1|s'));
    expect(String(sent('sendMessage')[0]?.body.text)).toMatch(/closed/);
    await t.run(async (ctx) => {
      expect(await ctx.db.query('billingOrders').collect()).toHaveLength(0);
    });
  });

  test('walks start, duration, quantity and shows only switched-on methods', async () => {
    const t = convexTest(schema, modules);
    await seed(t, { stars: false });
    const { sent, calls } = stubFetch();
    await post(t, message('/start'));
    expect(String(sent('sendMessage')[0]?.body.text)).toMatch(/gift codes/);
    await post(t, button('b|en'));
    const durations = calls.at(-1)!;
    expect(durations.method).toBe('editMessageText');
    // Only 3 and 12 months exist; 12 has no Stars price but crypto sells it.
    const kb = (durations.body.reply_markup as { inline_keyboard: { text: string }[][] })
      .inline_keyboard;
    expect(kb.flat().map((b) => b.text)).toEqual(['3 months', '12 months', 'Back']);
    await post(t, button('q|en|3|2'));
    const methods = (
      calls.at(-1)!.body.reply_markup as { inline_keyboard: { text: string }[][] }
    ).inline_keyboard
      .flat()
      .map((b) => b.text);
    expect(methods).toEqual(['Crypto, $28.00', 'Back']);
  });

  test('a forged button is ignored', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { sent, calls } = stubFetch();
    await post(t, button('p|en|3|999|s'));
    await post(t, button('k|en|not-a-ref'));
    expect(calls.map((c) => c.method)).toEqual(['answerCallbackQuery', 'answerCallbackQuery']);
    expect(sent('sendMessage')).toHaveLength(0);
  });
});

describe('Telegram Stars', () => {
  test('invoice, pre-checkout, payment, codes: exactly once', async () => {
    const t = convexTest(schema, modules);
    await seed(t);
    const { sent } = stubFetch();
    await post(t, button('p|en|3|2|s'));
    const invoice = sent('sendInvoice')[0]!.body;
    expect(invoice.currency).toBe('XTR');
    expect(invoice.provider_token).toBe('');
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
});

describe('crypto', () => {
  async function payIpn(t: ReturnType<typeof convexTest>, orderRef: string) {
    const payload = {
      payment_status: 'finished',
      payment_id: 4242,
      order_id: orderRef,
      price_amount: 14,
      price_currency: 'usd',
      actually_paid: 1,
      pay_amount: 1,
    };
    const sorted = JSON.stringify(payload, Object.keys(payload).sort());
    await t.action(internal.billing.ingestEvent, {
      processor: 'nowpayments',
      rawBody: JSON.stringify(payload),
      signature: await hmacSha512Hex(IPN_SECRET, sorted),
    });
  }

  test('hosted page, check, codes, saved-and-deleted; nothing keeps the chat', async () => {
    const t = convexTest(schema, modules);
    await seed(t, { stars: false });
    const { sent, calls } = stubFetch();
    await post(t, button('p|en|3|1|n'));
    const pay = calls.at(-1)!;
    const kb = (
      pay.body.reply_markup as {
        inline_keyboard: { text: string; url?: string; callback_data?: string }[][];
      }
    ).inline_keyboard.flat();
    expect(kb[0]).toMatchObject({ text: 'Open payment page', url: 'https://pay.example/i/inv_tg' });
    const check = kb[1]!.callback_data!;
    const ref = check.split('|')[2]!;

    await post(t, button(check));
    expect(String(sent('sendMessage').at(-1)!.body.text)).toMatch(/Not paid yet/);

    await payIpn(t, ref);
    // The buyer comes back through the processor's return link.
    await post(t, message(`/start o_${ref}`));
    const codes = sent('sendMessage').at(-1)!;
    expect(String(codes.body.text)).toMatch(/FSM-/);
    const saved = (codes.body.reply_markup as { inline_keyboard: { callback_data?: string }[][] })
      .inline_keyboard[0]![0]!.callback_data!;
    expect(saved).toBe(`a|en|${ref}`);

    await post(t, button(saved, 777));
    expect(sent('deleteMessage').at(-1)!.body).toEqual({ chat_id: CHAT, message_id: 777 });
    await post(t, button(check));
    expect(String(sent('sendMessage').at(-1)!.body.text)).toMatch(/already shown/);

    // Privacy: no table holds the chat id (the rate-limit subject is a salted HMAC).
    await t.run(async (ctx) => {
      for (const table of Object.keys(schema.tables)) {
        const rows = await ctx.db.query(table as 'users').collect();
        expect(JSON.stringify(rows), table).not.toContain(String(CHAT));
      }
    });
  });

  test('per-chat checkout limit', async () => {
    const t = convexTest(schema, modules);
    await seed(t, { stars: false });
    const { sent } = stubFetch();
    for (let i = 0; i < 7; i++) await post(t, button('p|en|3|1|n'));
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
