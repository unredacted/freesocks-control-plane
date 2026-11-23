/**
 * Admin -> Billing -> Telegram bot: the gift shop's settings, its webhook,
 * and the bot's command menu. The bot token is saved write-only from the card
 * (env TELEGRAM_BOT_TOKEN is the fallback); the webhook secret is made by
 * Register webhook when none is set (env TELEGRAM_WEBHOOK_SECRET is the
 * fallback). The view says only whether each is set, never a value.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import { upsertSettingRow } from './appSettings';
import { writeAuditLog } from './lib/audit';
import { resolveProcessorSecrets } from './lib/billingConfig';
import { randomHex } from './lib/crypto';
import {
  resolveTelegramConfig,
  resolveTelegramSecrets,
  telegramConfigWrites,
  TELEGRAM_SECRET_KEYS,
  WEBHOOK_SECRET_RE,
  type StarsPrice,
  type TelegramSecrets,
} from './lib/telegramConfig';
import * as tg from './lib/telegram/api';
import { BOT_LOCALES, trPlain, type BotLocale } from './lib/telegram/flow';

const WEBHOOK_PATH = '/api/webhooks/telegram';
const ALLOWED_UPDATES = ['message', 'callback_query', 'pre_checkout_query'];

export interface TelegramAdminView {
  enabled: boolean;
  botUsername: string;
  starsEnabled: boolean;
  starsPrices: StarsPrice[];
  tokenSet: boolean;
  secretSet: boolean;
  /** Where the webhook must point (null while PUBLIC_BASE_URL is unset). */
  webhookUrl: string | null;
}

export const view = internalQuery({
  args: {},
  handler: async (ctx): Promise<TelegramAdminView> => {
    const [cfg, secrets, tgSecrets] = await Promise.all([
      resolveTelegramConfig(ctx.db),
      resolveProcessorSecrets(ctx.db),
      resolveTelegramSecrets(ctx.db),
    ]);
    const base = (secrets.publicBaseUrl ?? '').replace(/\/$/, '');
    return {
      ...cfg,
      tokenSet: tgSecrets.botToken !== '',
      secretSet: tgSecrets.webhookSecret !== '',
      webhookUrl: base ? `${base}${WEBHOOK_PATH}` : null,
    };
  },
});

/** The bot's credentials, for the webhook route and the bot's actions only. */
export const secrets = internalQuery({
  args: {},
  handler: (ctx): Promise<TelegramSecrets> => resolveTelegramSecrets(ctx.db),
});

/**
 * Keep a freshly made webhook secret unless one is already saved (two
 * concurrent registers agree on the first). Returns the secret in force.
 */
export const saveWebhookSecret = internalMutation({
  args: { secret: v.string() },
  handler: async (ctx, { secret }): Promise<string> => {
    const cur = await resolveTelegramSecrets(ctx.db);
    if (cur.webhookSecret) return cur.webhookSecret;
    if (!WEBHOOK_SECRET_RE.test(secret)) throw new Error('bad webhook secret');
    await upsertSettingRow(ctx, TELEGRAM_SECRET_KEYS.webhookSecret, JSON.stringify(secret));
    return secret;
  },
});

export const setConfig = internalMutation({
  args: {
    enabled: v.optional(v.boolean()),
    botUsername: v.optional(v.string()),
    starsEnabled: v.optional(v.boolean()),
    starsPrices: v.optional(v.array(v.object({ months: v.number(), stars: v.number() }))),
    termsUrl: v.optional(v.string()),
    botToken: v.optional(v.string()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { actorAdminId, ...patch }): Promise<null> => {
    let writes: { key: string; value: unknown }[];
    try {
      writes = telegramConfigWrites(patch);
    } catch (err) {
      throw new ConvexError({
        code: 'validation',
        message: err instanceof Error ? err.message : 'Invalid Telegram settings',
      });
    }
    const cur = await resolveTelegramConfig(ctx.db);
    const nextUsername =
      patch.botUsername !== undefined
        ? ((writes.find((w) => w.key === 'telegram.botUsername')?.value as string) ?? '')
        : cur.botUsername;
    if ((patch.enabled ?? cur.enabled) && !nextUsername) {
      throw new ConvexError({
        code: 'validation',
        message: 'Set the bot username before opening the shop',
      });
    }
    for (const w of writes) {
      await upsertSettingRow(ctx, w.key, JSON.stringify(w.value), actorAdminId);
    }
    const next = await resolveTelegramConfig(ctx.db);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'admin.telegram.change',
      targetType: 'telegram',
      payload: {
        enabled: next.enabled,
        starsEnabled: next.starsEnabled,
        starsPriceCount: next.starsPrices.length,
        usernameChanged: next.botUsername !== cur.botUsername,
        tokenChanged: writes.some((w) => w.key === TELEGRAM_SECRET_KEYS.botToken),
      },
    });
    return null;
  },
});

export interface TelegramWebhookStatus {
  /** getWebhookInfo answered. */
  reachable: boolean;
  /** The webhook points at this deployment's route. */
  pointsHere: boolean;
  /** Any webhook at all is set. */
  set: boolean;
  pendingUpdates: number;
  lastErrorAt: string | null;
  lastErrorMessage: string | null;
  /** The token's bot username, to compare with the configured one. */
  tokenUsername: string | null;
}

/** Ask Telegram how the webhook stands (read-only). */
export const webhookStatus = internalAction({
  args: {},
  handler: async (ctx): Promise<TelegramWebhookStatus | null> => {
    const { botToken: token } = await ctx.runQuery(internal.telegramAdmin.secrets, {});
    if (!token) return null;
    const view = await ctx.runQuery(internal.telegramAdmin.view, {});
    try {
      const [info, me] = await Promise.all([tg.getWebhookInfo(token), tg.getMe(token)]);
      return {
        reachable: true,
        pointsHere: !!view.webhookUrl && info.url === view.webhookUrl,
        set: info.url !== '',
        pendingUpdates: info.pending_update_count,
        lastErrorAt: info.last_error_date
          ? new Date(info.last_error_date * 1000).toISOString()
          : null,
        lastErrorMessage: info.last_error_message?.slice(0, 200) ?? null,
        tokenUsername: me.username ?? null,
      };
    } catch {
      return {
        reachable: false,
        pointsHere: false,
        set: false,
        pendingUpdates: 0,
        lastErrorAt: null,
        lastErrorMessage: null,
        tokenUsername: null,
      };
    }
  },
});

function commandsFor(locale: BotLocale) {
  return [
    { command: 'buy', description: trPlain(locale, 'commandBuy') },
    { command: 'terms', description: trPlain(locale, 'commandTerms') },
    { command: 'paysupport', description: trPlain(locale, 'commandPaySupport') },
    { command: 'language', description: trPlain(locale, 'commandLanguage') },
    { command: 'privacy', description: trPlain(locale, 'commandPrivacy') },
    { command: 'help', description: trPlain(locale, 'commandHelp') },
  ];
}

/**
 * Point Telegram's webhook at this deployment (with the secret header) and
 * set the command menu in every language, or remove the webhook. Pending
 * updates are KEPT either way: they may hold Stars payments not yet granted.
 * Registering with no webhook secret set makes one (32 random bytes) and
 * saves it first, so the operator never has to pick one.
 */
export const setWebhook = internalAction({
  args: {
    action: v.union(v.literal('register'), v.literal('remove')),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a): Promise<{ ok: true }> => {
    const saved = await ctx.runQuery(internal.telegramAdmin.secrets, {});
    const token = saved.botToken;
    if (!token) {
      throw new ConvexError({ code: 'validation', message: 'Save the bot token first' });
    }
    try {
      if (a.action === 'remove') {
        await tg.deleteWebhook(token);
      } else {
        const view = await ctx.runQuery(internal.telegramAdmin.view, {});
        if (!view.webhookUrl) {
          throw new ConvexError({ code: 'validation', message: 'PUBLIC_BASE_URL is not set' });
        }
        const secret =
          saved.webhookSecret ||
          (await ctx.runMutation(internal.telegramAdmin.saveWebhookSecret, {
            secret: randomHex(32),
          }));
        await tg.setWebhook(token, view.webhookUrl, secret, ALLOWED_UPDATES);
        await tg.setMyCommands(token, commandsFor('en'));
        for (const l of BOT_LOCALES) {
          if (l !== 'en') await tg.setMyCommands(token, commandsFor(l), l);
        }
      }
    } catch (err) {
      if (err instanceof ConvexError) throw err;
      throw new ConvexError({
        code: 'upstream',
        message: err instanceof tg.TelegramApiError ? err.message : 'Telegram did not answer',
      });
    }
    await ctx.runMutation(internal.telegramAdmin.auditWebhook, {
      action: a.action,
      actorAdminId: a.actorAdminId,
    });
    return { ok: true };
  },
});

export const auditWebhook = internalMutation({
  args: {
    action: v.union(v.literal('register'), v.literal('remove')),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a): Promise<null> => {
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'admin.telegram.webhook',
      targetType: 'telegram',
      payload: { action: a.action },
    });
    return null;
  },
});
