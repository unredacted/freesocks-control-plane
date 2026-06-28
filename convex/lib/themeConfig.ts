/**
 * Theme config (W3-3). The brand palette is admin-selectable: a curated preset
 * (incl. a Classic monochrome) plus an optional hue override. Stored in the
 * `appSettings` `theme.*` namespace (like `ratelimit.*` / `billing.*`: NOT in
 * SETTINGS_DEFAULTS, so it doesn't leak through the generic settings allowlist
 * and gets typed validation here), resolved with a fail-safe default, and
 * exposed (non-secret) via publicConfig.get.
 *
 * THEME_PRESET_IDS mirrors the client's src/client/lib/theme.ts, which owns the
 * actual oklch values + the runtime applier. The server only validates the id
 * and the hue — it never needs the colour values.
 */
import type { DatabaseReader } from '../_generated/server';

export const THEME_PRESET_IDS = ['emerald', 'teal', 'indigo', 'classic'] as const;
export type ThemePresetId = (typeof THEME_PRESET_IDS)[number];
export const DEFAULT_THEME_PRESET: ThemePresetId = 'emerald';

export interface ThemeConfig {
  preset: ThemePresetId;
  /** oklch hue override in [0,360); null = use the preset's own hue. */
  hue: number | null;
}

export function isThemePresetId(v: unknown): v is ThemePresetId {
  return typeof v === 'string' && (THEME_PRESET_IDS as readonly string[]).includes(v);
}

/** A valid integer hue in [0,360) — or null (no override / invalid input). */
export function sanitizeHue(v: unknown): number | null {
  if (typeof v !== 'number' || !Number.isFinite(v)) return null;
  const h = Math.round(v);
  if (h < 0 || h > 360) return null;
  return h % 360; // fold 360 → 0
}

export async function resolveTheme(db: DatabaseReader): Promise<ThemeConfig> {
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
  const presetVal = await read('theme.preset');
  const hueVal = await read('theme.hue');
  return {
    preset: isThemePresetId(presetVal) ? presetVal : DEFAULT_THEME_PRESET,
    hue: sanitizeHue(hueVal),
  };
}
