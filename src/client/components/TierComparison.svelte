<script lang="ts">
  import Check from '@lucide/svelte/icons/check';
  import Minus from '@lucide/svelte/icons/minus';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { configQuery } from '../lib/queries';
  import { t } from '../lib/i18n/index.svelte';
  import { formatMoney } from '../lib/i18n/format';

  /**
   * Side-by-side feature comparison for free vs paid tiers. The bandwidth and
   * device numbers are pulled live from `/api/v1/config` (the actual
   * DB-enforced limits), so they can't drift from the seed; the static card
   * scaffold below supplies presentational copy (validity, mirrors) and a
   * fallback when config hasn't loaded. When billing is enabled, the membership
   * card shows a "from <price>/mo" and an Upgrade CTA (via `onUpgrade`, which the
   * parent wires to the purchase panel); otherwise it's purely informational.
   */
  interface Props {
    currentTierSlug: string;
    /** Called when the membership-card CTA is clicked (parent scrolls to / opens the panel). */
    onUpgrade?: () => void;
  }
  let { currentTierSlug, onUpgrade }: Props = $props();

  const config = configQuery();

  // Billing catalog (for the "from <price>/mo" line + whether to show a CTA).
  let billing = $derived(config.data?.billing);
  let billingEnabled = $derived(billing?.enabled ?? false);
  let fromPerMonthCents = $derived(
    (billing?.durations ?? []).reduce<number | null>((min, d) => {
      if (d.months <= 0) return min;
      const per = d.amountCents / d.months;
      return min === null || per < min ? per : min;
    }, null),
  );
  let fromPerMonth = $derived(
    fromPerMonthCents !== null
      ? formatMoney(Math.round(fromPerMonthCents), billing?.currency ?? 'USD')
      : null,
  );

  interface TierCard {
    slug: string;
    name: string;
    features: {
      bandwidth: string;
      devices: string;
      validity: string;
      mirrors: boolean;
    };
  }
  const tiers: TierCard[] = [
    {
      slug: 'free',
      name: 'Free',
      features: {
        bandwidth: '50 GB / month',
        devices: '1 device',
        validity: '30-day key',
        mirrors: true,
      },
    },
    {
      slug: 'member',
      name: 'FreeSocks Membership',
      features: {
        bandwidth: 'Unlimited',
        devices: 'Unlimited',
        validity: 'Continuous',
        mirrors: true,
      },
    },
  ];

  // Live, DB-enforced limits keyed by slug; overlaid onto the scaffold above.
  const liveLimits = $derived(new Map((config.data?.tiers ?? []).map((t) => [t.slug, t])));
  function bandwidthLabel(slug: string, fallback: string): string {
    const tier = liveLimits.get(slug);
    if (!tier) return fallback;
    return tier.monthlyTrafficGb === 0
      ? t('hero.unlimited')
      : t('tiers.gbPerMonth', { gb: tier.monthlyTrafficGb });
  }
  function deviceLabel(slug: string, fallback: string): string {
    const tier = liveLimits.get(slug);
    if (!tier) return fallback;
    // deviceLimit 0 is the "unlimited" sentinel (matches monthlyTrafficGb 0).
    return tier.deviceLimit === 0
      ? t('hero.unlimited')
      : t('common.deviceCount', { count: tier.deviceLimit });
  }
</script>

<section class="space-y-4">
  <div>
    <h2 class="text-xl font-display font-bold tracking-tight">{t('tiers.title')}</h2>
    <p class="text-sm text-muted-foreground">
      {t('tiers.subtitle')}
    </p>
  </div>

  <div class="grid gap-3 md:grid-cols-2">
    {#each tiers as tier (tier.slug)}
      {@const isCurrent = tier.slug === currentTierSlug}
      <div
        class="rounded-xl border p-5 space-y-4 relative overflow-hidden bg-card {isCurrent
          ? 'ring-1 ring-primary/30 border-primary/30'
          : 'border-border'}"
      >
        {#if isCurrent}
          <div
            class="absolute top-0 start-0 px-2 py-1 rounded-ee-lg bg-secondary text-secondary-foreground text-[10px] font-semibold uppercase tracking-wider"
          >
            {t('tiers.yourTier')}
          </div>
        {/if}

        <div class="space-y-1 pt-3">
          <h3 class="text-lg font-display font-semibold">{tier.name}</h3>
          {#if tier.slug === 'member' && billingEnabled && fromPerMonth}
            <p class="text-sm tabular-nums text-muted-foreground">
              {t('upgrade.perMonth', { price: fromPerMonth })}
            </p>
          {/if}
        </div>

        <ul class="space-y-2 text-sm">
          <li class="flex items-start gap-2">
            <Check class="size-4 text-primary shrink-0 mt-0.5" />
            {#if config.isPending}
              <Skeleton class="h-4 w-28" />
            {:else}
              <span class="tabular-nums">{bandwidthLabel(tier.slug, tier.features.bandwidth)}</span>
            {/if}
          </li>
          <li class="flex items-start gap-2">
            <Check class="size-4 text-primary shrink-0 mt-0.5" />
            {#if config.isPending}
              <Skeleton class="h-4 w-20" />
            {:else}
              <span class="tabular-nums">{deviceLabel(tier.slug, tier.features.devices)}</span>
            {/if}
          </li>
          <li class="flex items-start gap-2">
            <Check class="size-4 text-primary shrink-0 mt-0.5" />
            <span>
              {tier.features.validity === 'Continuous'
                ? t('tiers.validityContinuous')
                : t('tiers.validity30')}
            </span>
          </li>
          <li class="flex items-start gap-2">
            {#if tier.features.mirrors}
              <Check class="size-4 text-primary shrink-0 mt-0.5" />
            {:else}
              <Minus class="size-4 text-muted-foreground/40 shrink-0 mt-0.5" />
            {/if}
            <span class="text-muted-foreground">{t('tiers.mirrors')}</span>
          </li>
        </ul>

        {#if !isCurrent && tier.slug !== 'free' && billingEnabled && onUpgrade}
          <Button variant="default" class="w-full" size="sm" onclick={onUpgrade}>
            {t('tiers.upgradeCta')}
          </Button>
        {/if}
      </div>
    {/each}
  </div>
</section>
