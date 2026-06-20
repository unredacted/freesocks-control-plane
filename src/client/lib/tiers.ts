import type { PublicConfig } from '../../shared/contracts/auth';

/**
 * Small helpers for reading tier values out of the public config so the SPA
 * shows the admin-set DB numbers (never hardcoded copies that drift). The
 * `0 = unlimited` sentinel matches the comparison cards (TierComparison.svelte)
 * and the server's issuance logic.
 */
type Tier = PublicConfig['tiers'][number];

/** The default-free tier (slug `free`). */
export function freeTier(config: PublicConfig | undefined): Tier | undefined {
  return config?.tiers.find((t) => t.slug === 'free');
}

/** The paid membership tier (the slug billing maps to; default `member`). */
export function membershipTier(config: PublicConfig | undefined): Tier | undefined {
  const slug = config?.billing?.tierSlug ?? 'member';
  return config?.tiers.find((t) => t.slug === slug);
}

/** Structured tier limits, so the *words* live in the i18n catalog (the Home
 *  page composes the translated phrase) while the *numbers* stay DB-driven here.
 *  `0 = unlimited` matches the comparison cards + the server's issuance logic. */
export interface TierLimits {
  unlimitedBandwidth: boolean;
  gb: number;
  unlimitedDevices: boolean;
  devices: number;
}

/**
 * Read a tier's bandwidth/device limits as structured data. Falls back to
 * fully-unlimited when the tier is missing (the membership tier is unlimited by
 * product design). The Home page turns this into a localized phrase via t().
 */
export function tierLimits(tier: Tier | undefined): TierLimits {
  if (!tier) return { unlimitedBandwidth: true, gb: 0, unlimitedDevices: true, devices: 0 };
  return {
    unlimitedBandwidth: tier.monthlyTrafficGb === 0,
    gb: tier.monthlyTrafficGb,
    unlimitedDevices: tier.deviceLimit === 0,
    devices: tier.deviceLimit,
  };
}
