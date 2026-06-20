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

/**
 * English limits phrase for the English-only Home page (other surfaces use the
 * i18n'd comparison cards). e.g. "unlimited bandwidth and devices" or
 * "100 GB / month and up to 3 devices". Falls back to the unlimited phrasing
 * when the tier is missing (the membership tier is unlimited by product design).
 */
export function limitsPhrase(tier: Tier | undefined): string {
  if (!tier) return 'unlimited bandwidth and devices';
  const gbUnlimited = tier.monthlyTrafficGb === 0;
  const devUnlimited = tier.deviceLimit === 0;
  if (gbUnlimited && devUnlimited) return 'unlimited bandwidth and devices';
  const bw = gbUnlimited ? 'unlimited bandwidth' : `${tier.monthlyTrafficGb} GB / month`;
  const dev = devUnlimited
    ? 'unlimited devices'
    : `up to ${tier.deviceLimit} device${tier.deviceLimit === 1 ? '' : 's'}`;
  return `${bw} and ${dev}`;
}
