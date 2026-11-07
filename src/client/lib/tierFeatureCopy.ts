/**
 * The words of a plan-card feature line: the operator's own text wins
 * (verbatim, every language), else the built-in preset's translated copy.
 */
import { t, type MessageKey } from './i18n/index.svelte';
import type { TierFeaturePreset } from '../../shared/contracts/tierFeatures';

const PRESET_KEYS: Record<TierFeaturePreset, MessageKey> = {
  fasterSpeeds: 'tiers.feature.fasterSpeeds',
  alternateLocations: 'tiers.feature.alternateLocations',
  mirrors: 'tiers.feature.mirrors',
  supportsFree: 'tiers.feature.supportsFree',
};

export function tierFeatureText(f: {
  preset: TierFeaturePreset | null;
  label: string | null;
}): string {
  const own = f.label?.trim();
  if (own) return own;
  return f.preset ? t(PRESET_KEYS[f.preset]) : '';
}

/** English names of the presets, for the (English-only) admin editor. */
export const PRESET_ADMIN_NAMES: Record<TierFeaturePreset, string> = {
  fasterSpeeds: 'Faster speeds',
  alternateLocations: 'Alternate locations',
  mirrors: 'Mirror links if the main one is blocked',
  supportsFree: 'Helps keep free accounts running',
};
