/**
 * Plan-card feature icons: the fixed set an operator picks from in Admin → Tiers
 * (src/shared/contracts/tierFeatures.ts holds the id list). The Record over the
 * union makes a missing icon a compile error; an unknown id (a newer server)
 * renders the check mark.
 */
import type { Component } from 'svelte';
import Check from '@lucide/svelte/icons/check';
import EyeOff from '@lucide/svelte/icons/eye-off';
import Gauge from '@lucide/svelte/icons/gauge';
import Globe from '@lucide/svelte/icons/globe';
import Heart from '@lucide/svelte/icons/heart';
import InfinityIcon from '@lucide/svelte/icons/infinity';
import Layers from '@lucide/svelte/icons/layers';
import Lock from '@lucide/svelte/icons/lock';
import MapPin from '@lucide/svelte/icons/map-pin';
import Rocket from '@lucide/svelte/icons/rocket';
import SatelliteDish from '@lucide/svelte/icons/satellite-dish';
import Shield from '@lucide/svelte/icons/shield';
import ShieldCheck from '@lucide/svelte/icons/shield-check';
import Waves from '@lucide/svelte/icons/waves';
import Wifi from '@lucide/svelte/icons/wifi';
import Zap from '@lucide/svelte/icons/zap';
import { isTierFeatureIconId, type TierFeatureIconId } from '../../shared/contracts/tierFeatures';

export const TIER_FEATURE_ICONS: Record<TierFeatureIconId, Component> = {
  check: Check,
  infinity: InfinityIcon,
  zap: Zap,
  gauge: Gauge,
  'map-pin': MapPin,
  globe: Globe,
  layers: Layers,
  heart: Heart,
  'shield-check': ShieldCheck,
  shield: Shield,
  lock: Lock,
  'eye-off': EyeOff,
  wifi: Wifi,
  rocket: Rocket,
  'satellite-dish': SatelliteDish,
  waves: Waves,
};

export function resolveTierFeatureIcon(iconId: string | null | undefined): Component {
  return isTierFeatureIconId(iconId) ? TIER_FEATURE_ICONS[iconId] : Check;
}
