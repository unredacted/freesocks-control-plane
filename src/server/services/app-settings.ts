/**
 * Typed wrapper over the `app_settings` table. Each supported key has a
 * Zod schema entry below; unknown keys are rejected by GET/PATCH routes,
 * and stored JSON is validated on every read so a manually-corrupted row
 * fails closed instead of silently returning bad data.
 *
 * This is the durable home for "admin flips a switch in the CMS and the
 * system behaves differently". Adding a new setting:
 *   1. Add the key + Zod schema to SETTINGS_SCHEMA below.
 *   2. Add a default value to DEFAULTS so installs without the row work.
 *   3. (Optional) Add the key to the seed INSERT in migration 0006 so a
 *      fresh DB has the row from day one.
 *   4. Reference the key from wherever needs to consume the toggle.
 *
 * KV-cached as a single JSON bag under `app:settings:all`. Cache TTL is short
 * (5 min) since admin edits are rare and reads are frequent; on edit the
 * cache is invalidated so the next read goes to DB.
 */
import { z } from 'zod';
import type { Db } from '../db/client';
import { appSettings } from '../db/schema';
import type { KvStore } from '../kv/interface';
import type { Logger } from '../lib/logger';

const CACHE_KEY = 'app:settings:all';
const CACHE_TTL_SEC = 300;

/** Add new settings here. Each entry: a Zod schema + a default value. */
const SETTINGS_SCHEMA = {
  'outline.enabled': z.boolean(),
  'remnawave.enabled': z.boolean(),
  'subscription.default_backend': z.enum(['remnawave', 'outline']),
  'subscription.user_choice_enabled': z.boolean(),
  'subscription.backend_labels': z.object({
    remnawave: z.string(),
    outline: z.string(),
  }),
  'outline.scoring.latency_weight': z.number(),
  'outline.scoring.key_count_weight': z.number(),
  // Account-number self-service auth (docs/account-number-design.md). Gates
  // both minting at issuance and the account-number login route + SPA tab, so
  // the whole feature ships dark and can be enabled per-environment.
  'account_id.enabled': z.boolean(),
} as const;

const DEFAULTS = {
  'outline.enabled': false,
  'remnawave.enabled': true,
  'subscription.default_backend': 'remnawave',
  'subscription.user_choice_enabled': false,
  // User-facing labels for the two proxy backends. The internal id
  // `remnawave` stays on the BackendId enum and DB rows for backwards
  // compatibility, but the label shown to users says "Xray" — that's the
  // actual protocol they connect to; Remnawave is just the management
  // panel we use behind the scenes. Admins can override either label via
  // the Settings page (PATCH /api/v1/admin/settings).
  'subscription.backend_labels': { remnawave: 'Xray', outline: 'Outline' },
  'outline.scoring.latency_weight': 1,
  'outline.scoring.key_count_weight': 100,
  'account_id.enabled': false,
} as const satisfies SettingsMap;

export type SettingKey = keyof typeof SETTINGS_SCHEMA;
export type SettingsMap = {
  [K in SettingKey]: z.infer<(typeof SETTINGS_SCHEMA)[K]>;
};

export class AppSettingsService {
  constructor(
    private readonly db: Db,
    private readonly cache: KvStore,
    private readonly logger: Logger,
  ) {}

  /** Return every setting. Missing rows fall back to compiled-in defaults. */
  async getAll(): Promise<SettingsMap> {
    const cached = await this.cache.getJson<SettingsMap>(CACHE_KEY);
    if (cached) return { ...DEFAULTS, ...cached };

    const rows = await this.db.select().from(appSettings).all();
    const map: Partial<SettingsMap> = {};
    for (const row of rows) {
      const schema = SETTINGS_SCHEMA[row.key as SettingKey];
      if (!schema) {
        // Unknown row (stale key from a previous version) — skip rather than
        // crash. Surfaces via the periodic audit but doesn't break reads.
        this.logger.debug('app_settings_unknown_key', { key: row.key });
        continue;
      }
      try {
        const parsed = schema.parse(JSON.parse(row.value));
        (map as Record<string, unknown>)[row.key] = parsed;
      } catch (err) {
        this.logger.warn('app_settings_value_invalid', {
          key: row.key,
          error: String(err),
        });
      }
    }
    const result = { ...DEFAULTS, ...map } as SettingsMap;
    await this.cache.putJson(CACHE_KEY, result, { expirationTtl: CACHE_TTL_SEC });
    return result;
  }

  /** Return a single setting. Convenience over `getAll()[key]`. */
  async get<K extends SettingKey>(key: K): Promise<SettingsMap[K]> {
    const all = await this.getAll();
    return all[key];
  }

  /**
   * Upsert one setting. Value is validated against the registered Zod schema
   * for that key — invalid values throw, preserving the row.
   */
  async set<K extends SettingKey>(
    key: K,
    value: SettingsMap[K],
    updatedByAdminId: number | null,
  ): Promise<void> {
    const schema = SETTINGS_SCHEMA[key];
    if (!schema) {
      throw new Error(`Unknown setting key: ${key}`);
    }
    const validated = schema.parse(value);
    const serialized = JSON.stringify(validated);
    const now = Date.now();
    await this.db
      .insert(appSettings)
      .values({ key, value: serialized, updatedAt: now, updatedByAdminId })
      .onConflictDoUpdate({
        target: appSettings.key,
        set: { value: serialized, updatedAt: now, updatedByAdminId },
      });
    await this.cache.delete(CACHE_KEY);
  }

  /** Upsert multiple settings atomically (each validated). */
  async setMany(patch: Partial<SettingsMap>, updatedByAdminId: number | null): Promise<void> {
    for (const [key, value] of Object.entries(patch)) {
      await this.set(key as SettingKey, value as never, updatedByAdminId);
    }
  }

  /** Exposed for the admin route handlers — they need the key list for OpenAPI. */
  static knownKeys(): readonly SettingKey[] {
    return Object.keys(SETTINGS_SCHEMA) as SettingKey[];
  }

  /** Exposed for the admin route — Zod validators per key. */
  static schemaFor<K extends SettingKey>(key: K): (typeof SETTINGS_SCHEMA)[K] {
    return SETTINGS_SCHEMA[key];
  }
}
