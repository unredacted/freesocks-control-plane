/**
 * Plan-card feature lines (Admin → Tiers → Card features). Each tier carries an
 * ordered list of lines shown under its bandwidth/device limits on every plan
 * card (Home, sign-up, account, the payment form). A line is a BUILT-IN preset
 * (translated in the SPA) or the operator's own text (shown verbatim in every
 * language), with an icon picked from a fixed set (never free-form: the SPA maps
 * ids to bundled icons; an unknown id renders the check mark).
 *
 * Pure + shared: the Convex side validates writes with `validateTierFeatures`
 * and fills an unset list with `defaultTierFeatures`; the SPA reads the shapes.
 */
import { z } from 'zod';

/** The icons a feature line may use (the mode-family set plus four more). */
export const TIER_FEATURE_ICON_IDS = [
  'check',
  'infinity',
  'zap',
  'gauge',
  'map-pin',
  'globe',
  'layers',
  'heart',
  'shield-check',
  'shield',
  'lock',
  'eye-off',
  'wifi',
  'rocket',
  'satellite-dish',
  'waves',
] as const;
export type TierFeatureIconId = (typeof TIER_FEATURE_ICON_IDS)[number];

/** Built-in lines (their words live in the SPA catalogs under `tiers.feature.*`). */
export const TIER_FEATURE_PRESETS = [
  'fasterSpeeds',
  'alternateLocations',
  'mirrors',
  'supportsFree',
] as const;
export type TierFeaturePreset = (typeof TIER_FEATURE_PRESETS)[number];

/** The icon a preset gets when the operator adds it. */
export const PRESET_ICONS: Record<TierFeaturePreset, TierFeatureIconId> = {
  fasterSpeeds: 'zap',
  alternateLocations: 'map-pin',
  mirrors: 'layers',
  supportsFree: 'heart',
};

export const MAX_TIER_FEATURES = 8;
export const MAX_TIER_FEATURE_LABEL = 80;

export interface TierFeature {
  /** A built-in line, or null for the operator's own text. */
  preset: TierFeaturePreset | null;
  iconId: TierFeatureIconId;
  /** The operator's words: replaces the preset's translated copy when set. */
  label: string | null;
}

export const TierFeatureSchema = z.object({
  preset: z.enum(TIER_FEATURE_PRESETS).nullable(),
  // Tolerant on read (an older SPA meeting a newer icon renders the check).
  iconId: z.string(),
  label: z.string().nullable(),
});
/** A line as it travels (the icon id is checked on render, not on parse). */
export type TierFeatureWire = z.infer<typeof TierFeatureSchema>;

export function isTierFeatureIconId(v: unknown): v is TierFeatureIconId {
  return typeof v === 'string' && (TIER_FEATURE_ICON_IDS as readonly string[]).includes(v);
}

export function isTierFeaturePreset(v: unknown): v is TierFeaturePreset {
  return typeof v === 'string' && (TIER_FEATURE_PRESETS as readonly string[]).includes(v);
}

const preset = (p: TierFeaturePreset): TierFeature => ({
  preset: p,
  iconId: PRESET_ICONS[p],
  label: null,
});

/**
 * The lines a tier shows while the operator has not set its list: the free
 * tier names the mirrors, every other tier the membership extras.
 */
export function defaultTierFeatures(isDefaultFree: boolean): TierFeature[] {
  return isDefaultFree
    ? [preset('mirrors')]
    : [
        preset('fasterSpeeds'),
        preset('alternateLocations'),
        preset('mirrors'),
        preset('supportsFree'),
      ];
}

/**
 * Validate + normalize an admin write. Returns the cleaned list, or an error
 * message naming the first bad line (1-based). Labels are trimmed; a blank
 * label on a preset means "use the translated copy"; a line with neither a
 * preset nor text is refused.
 */
export function validateTierFeatures(
  raw: unknown,
): { ok: true; features: TierFeature[] } | { ok: false; message: string } {
  if (!Array.isArray(raw)) return { ok: false, message: 'features must be a list' };
  if (raw.length > MAX_TIER_FEATURES)
    return { ok: false, message: `at most ${MAX_TIER_FEATURES} feature lines` };
  const out: TierFeature[] = [];
  for (const [i, entry] of raw.entries()) {
    const n = i + 1;
    if (!entry || typeof entry !== 'object') return { ok: false, message: `line ${n} is invalid` };
    const e = entry as { preset?: unknown; iconId?: unknown; label?: unknown };
    const p = e.preset ?? null;
    if (p !== null && !isTierFeaturePreset(p))
      return { ok: false, message: `line ${n}: unknown built-in line` };
    if (!isTierFeatureIconId(e.iconId)) return { ok: false, message: `line ${n}: unknown icon` };
    if (e.label != null && typeof e.label !== 'string')
      return { ok: false, message: `line ${n}: text must be a string` };
    const label = typeof e.label === 'string' ? e.label.trim() : '';
    if (label.length > MAX_TIER_FEATURE_LABEL)
      return { ok: false, message: `line ${n}: at most ${MAX_TIER_FEATURE_LABEL} characters` };
    if (p === null && label.length === 0)
      return { ok: false, message: `line ${n}: needs text or a built-in line` };
    out.push({ preset: p, iconId: e.iconId, label: label.length > 0 ? label : null });
  }
  return { ok: true, features: out };
}

/** The stored list, or the defaults when the tier has none set. */
export function resolveTierFeatures(
  stored: readonly TierFeature[] | undefined | null,
  isDefaultFree: boolean,
): TierFeature[] {
  return stored ? stored.map((f) => ({ ...f })) : defaultTierFeatures(isDefaultFree);
}
