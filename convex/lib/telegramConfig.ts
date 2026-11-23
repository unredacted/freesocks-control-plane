/**
 * Telegram gift shop config (docs/billing.md § "Telegram gift shop"). Stored
 * in the `appSettings` `telegram.*` namespace (like `alerts.*`: NOT in
 * SETTINGS_DEFAULTS, so it gets typed validation here and never leaks through
 * the generic settings allowlist). Ships OFF: the bot answers "closed" until
 * an admin turns the shop on, and each payment method has its own switch.
 *
 * SECRETS are env only and never stored here: TELEGRAM_BOT_TOKEN (the
 * BotFather token, which is also part of every Bot API URL) and
 * TELEGRAM_WEBHOOK_SECRET (the `secret_token` Telegram echoes in the
 * x-telegram-bot-api-secret-token header of every update).
 */
import type { DatabaseReader } from '../_generated/server';

export interface StarsPrice {
  months: number;
  /** Whole Telegram Stars for ONE code of this duration. */
  stars: number;
}

export interface TelegramConfig {
  /** The shop. Off = the bot only says it is closed. */
  enabled: boolean;
  /** The bot's public @username, without the @ ('' = unset). */
  botUsername: string;
  /** Telegram Stars payments (still needs a Stars price for a duration). */
  starsEnabled: boolean;
  starsPrices: StarsPrice[];
  /** Crypto on our own rails (NOWPayments / BTCPay; each also needs its billing rail on). */
  cryptoEnabled: boolean;
}

export const TELEGRAM_KEYS = {
  enabled: 'telegram.enabled',
  botUsername: 'telegram.botUsername',
  starsEnabled: 'telegram.stars.enabled',
  starsPrices: 'telegram.stars.prices',
  cryptoEnabled: 'telegram.crypto.enabled',
} as const;

export const TELEGRAM_DEFAULTS: TelegramConfig = {
  enabled: false,
  botUsername: '',
  starsEnabled: false,
  starsPrices: [],
  cryptoEnabled: false,
};

/** The rails the bot may offer for crypto: the ones with a direct (in-chat) checkout. */
export const TELEGRAM_CRYPTO_RAILS = ['nowpayments', 'btcpay'] as const;
export type TelegramCryptoRail = (typeof TELEGRAM_CRYPTO_RAILS)[number];

/** Upper bound on a Stars price per code (Telegram caps one invoice at 10,000 Stars x quantity anyway). */
export const MAX_STARS_PER_CODE = 100_000;

/** A Telegram bot username as BotFather allows it, with an optional leading @; else ''. */
export function sanitizeBotUsername(v: unknown): string {
  if (typeof v !== 'string') return '';
  const s = v.trim().replace(/^@/, '');
  return /^[A-Za-z0-9_]{5,32}$/.test(s) ? s : '';
}

/**
 * Stars prices: whole months 1-36 and whole Stars 1..MAX_STARS_PER_CODE,
 * one per duration (the first wins), sorted by months. Anything invalid is
 * dropped. Returns null when the input isn't an array at all.
 */
export function sanitizeStarsPrices(v: unknown): StarsPrice[] | null {
  if (!Array.isArray(v)) return null;
  const seen = new Set<number>();
  const out: StarsPrice[] = [];
  for (const row of v) {
    if (!row || typeof row !== 'object') continue;
    const { months, stars } = row as Record<string, unknown>;
    if (typeof months !== 'number' || !Number.isInteger(months) || months < 1 || months > 36) {
      continue;
    }
    if (
      typeof stars !== 'number' ||
      !Number.isInteger(stars) ||
      stars < 1 ||
      stars > MAX_STARS_PER_CODE
    ) {
      continue;
    }
    if (seen.has(months)) continue;
    seen.add(months);
    out.push({ months, stars });
  }
  return out.sort((a, b) => a.months - b.months);
}

export async function resolveTelegramConfig(db: DatabaseReader): Promise<TelegramConfig> {
  const read = async (key: string): Promise<unknown> => {
    const row = await db
      .query('appSettings')
      .withIndex('by_key', (q) => q.eq('key', key))
      .unique();
    if (!row) return undefined;
    try {
      return JSON.parse(row.value);
    } catch {
      return undefined;
    }
  };
  const [enabled, botUsername, starsEnabled, starsPrices, cryptoEnabled] = await Promise.all([
    read(TELEGRAM_KEYS.enabled),
    read(TELEGRAM_KEYS.botUsername),
    read(TELEGRAM_KEYS.starsEnabled),
    read(TELEGRAM_KEYS.starsPrices),
    read(TELEGRAM_KEYS.cryptoEnabled),
  ]);
  return {
    enabled: enabled === true,
    botUsername: sanitizeBotUsername(botUsername),
    starsEnabled: starsEnabled === true,
    starsPrices: sanitizeStarsPrices(starsPrices) ?? [],
    cryptoEnabled: cryptoEnabled === true,
  };
}

export interface TelegramConfigPatch {
  enabled?: boolean;
  botUsername?: string;
  starsEnabled?: boolean;
  starsPrices?: unknown;
  cryptoEnabled?: boolean;
}

/**
 * Validate an admin patch into appSettings writes. Throws a plain Error with
 * a reason on a bad field (the caller maps it to a validation error); an
 * empty bot username clears it.
 */
export function telegramConfigWrites(
  patch: TelegramConfigPatch,
): { key: string; value: unknown }[] {
  const writes: { key: string; value: unknown }[] = [];
  const bool = (name: keyof TelegramConfigPatch, key: string) => {
    const v = patch[name];
    if (v === undefined) return;
    if (typeof v !== 'boolean') throw new Error(`${name} must be true or false`);
    writes.push({ key, value: v });
  };
  bool('enabled', TELEGRAM_KEYS.enabled);
  bool('starsEnabled', TELEGRAM_KEYS.starsEnabled);
  bool('cryptoEnabled', TELEGRAM_KEYS.cryptoEnabled);
  if (patch.botUsername !== undefined) {
    const raw = typeof patch.botUsername === 'string' ? patch.botUsername.trim() : null;
    if (raw === null) throw new Error('botUsername must be text');
    const name = sanitizeBotUsername(raw);
    if (raw !== '' && !name) {
      throw new Error('botUsername must be 5 to 32 letters, digits or underscores');
    }
    writes.push({ key: TELEGRAM_KEYS.botUsername, value: name });
  }
  if (patch.starsPrices !== undefined) {
    const prices = sanitizeStarsPrices(patch.starsPrices);
    if (!prices || prices.length !== (patch.starsPrices as unknown[]).length) {
      throw new Error(
        `starsPrices must be a list of { months: 1-36, stars: 1-${MAX_STARS_PER_CODE} }, one per duration`,
      );
    }
    writes.push({ key: TELEGRAM_KEYS.starsPrices, value: prices });
  }
  return writes;
}
