/**
 * The family icon registry: a curated, statically-imported Lucide set keyed by
 * the OPEN `iconId` string the catalog rows carry (the SCHEME_IDS pattern —
 * DB references an id, code owns the artifact). Admin-created families pick
 * one in the editor; an unknown/missing id falls back to the default so a
 * stale row can never break the picker. Static imports keep the bundle
 * bounded and tree-shaken. The id LIST lives in connectionModeIconIds.ts
 * (pure, .svelte-free) so tests and the admin select need not load components;
 * the Record over its union makes id↔icon exhaustiveness a compile error.
 */
import type { Component } from 'svelte';
import EyeOff from '@lucide/svelte/icons/eye-off';
import Gauge from '@lucide/svelte/icons/gauge';
import Globe from '@lucide/svelte/icons/globe';
import Layers from '@lucide/svelte/icons/layers';
import Lock from '@lucide/svelte/icons/lock';
import Rocket from '@lucide/svelte/icons/rocket';
import SatelliteDish from '@lucide/svelte/icons/satellite-dish';
import Shield from '@lucide/svelte/icons/shield';
import ShieldCheck from '@lucide/svelte/icons/shield-check';
import Waves from '@lucide/svelte/icons/waves';
import Wifi from '@lucide/svelte/icons/wifi';
import Zap from '@lucide/svelte/icons/zap';
import { DEFAULT_MODE_ICON_ID, isModeIconId, type ModeIconId } from './connectionModeIconIds';

export { MODE_ICON_IDS } from './connectionModeIconIds';
export type { ModeIconId } from './connectionModeIconIds';

export const MODE_ICONS: Record<ModeIconId, Component> = {
  zap: Zap,
  'shield-check': ShieldCheck,
  shield: Shield,
  globe: Globe,
  lock: Lock,
  'eye-off': EyeOff,
  wifi: Wifi,
  rocket: Rocket,
  layers: Layers,
  gauge: Gauge,
  'satellite-dish': SatelliteDish,
  waves: Waves,
};

export const DEFAULT_MODE_ICON: Component = MODE_ICONS[DEFAULT_MODE_ICON_ID];

export function resolveModeIcon(iconId: string | null | undefined): Component {
  return isModeIconId(iconId) ? MODE_ICONS[iconId] : DEFAULT_MODE_ICON;
}

/** The icon for a family projection (wire `iconId` → component). */
export function familyIcon(f: { iconId?: string | null }): Component {
  return resolveModeIcon(f.iconId);
}
