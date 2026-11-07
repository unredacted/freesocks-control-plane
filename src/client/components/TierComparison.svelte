<script lang="ts">
  import Check from '@lucide/svelte/icons/check';
  import Gauge from '@lucide/svelte/icons/gauge';
  import InfinityIcon from '@lucide/svelte/icons/infinity';
  import { resolveTierFeatureIcon } from '../lib/tierFeatureIcons';
  import { tierFeatureText } from '../lib/tierFeatureCopy';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { configQuery } from '../lib/queries';
  import { t, type MessageKey } from '../lib/i18n/index.svelte';
  import { formatMoney } from '../lib/i18n/format';
  import { baselinePerMonth } from '../lib/billing';
  import { deviceLimitsShown } from '../lib/tiers';

  /**
   * Tier comparison cards, rendered ENTIRELY from `/api/v1/config` - name,
   * description, and the bandwidth/device limits are the live DB values, so
   * Admin → Tiers edits propagate here (and to every other view that renders
   * this) with no hardcoded copy to drift. The membership tier (the one whose
   * slug matches `billing.tierSlug`) shows its monthly price (the shortest term's
   * per-month) + an Upgrade CTA when billing is enabled and the parent supplies
   * `onUpgrade`. Longer-term discounts are shown in the upgrade backend, not here.
   */
  interface Props {
    currentTierSlug: string;
    /** Called when the membership-card CTA is clicked (parent scrolls to / opens the backend). */
    onUpgrade?: () => void;
    /** Per-surface header copy (the RedeemCode pattern); defaults keep Home unchanged. */
    titleKey?: MessageKey;
    subtitleKey?: MessageKey;
    /** Leave the header out when the surrounding section already titles it. */
    hideHeader?: boolean;
  }
  let {
    currentTierSlug,
    onUpgrade,
    titleKey = 'tiers.title',
    subtitleKey = 'tiers.subtitle',
    hideHeader = false,
  }: Props = $props();

  const config = configQuery();
  let tiers = $derived(config.data?.tiers ?? []);
  let billing = $derived(config.data?.billing);
  let billingEnabled = $derived(billing?.enabled ?? false);
  let membershipSlug = $derived(billing?.tierSlug ?? 'member');
  // Device limits are an opt-in Remnawave feature; hide the device row entirely
  // when the admin enforcement toggle is off (the default unlimited posture).
  let showDevices = $derived(deviceLimitsShown(config.data));

  // The headline monthly price = the SHORTEST term's per-month (e.g. the 1-month
  // plan at $5/mo), NOT the cheapest amortized annual ($4.17/mo) - that read as a
  // pricing bug. Longer-term discounts live in the upgrade backend instead.
  let monthlyCents = $derived(baselinePerMonth(billing?.durations ?? []));
  let fromPerMonth = $derived(
    monthlyCents !== null
      ? formatMoney(Math.round(monthlyCents), billing?.currency ?? 'USD')
      : null,
  );

  // 0 is the "unlimited" sentinel for both limits.
  const bandwidthLabel = (gb: number): string =>
    gb === 0 ? t('hero.unlimited') : t('tiers.gbPerMonth', { gb });
  const deviceLabel = (n: number): string =>
    n === 0 ? t('hero.unlimited') : t('common.deviceCount', { count: n });
</script>

<section class="space-y-4">
  {#if !hideHeader}
    <div>
      <h2 class="font-display text-xl font-bold tracking-tight">{t(titleKey)}</h2>
      <p class="text-sm text-muted-foreground">{t(subtitleKey)}</p>
    </div>
  {/if}

  {#if config.isPending}
    <div class="grid gap-3 sm:grid-cols-2">
      <Skeleton class="h-48 w-full" />
      <Skeleton class="h-48 w-full" />
    </div>
  {:else}
    <div class="grid items-start gap-3 sm:grid-cols-2">
      {#each tiers as tier (tier.slug)}
        {@const isCurrent = tier.slug === currentTierSlug}
        {@const isMembership = tier.slug === membershipSlug}
        {@const spotlight = isMembership && billingEnabled}
        <div
          class="relative overflow-hidden rounded-lg bg-card {spotlight
            ? 'border-2 border-primary'
            : isCurrent
              ? 'border border-primary/40'
              : 'border border-border'}"
        >
          {#if spotlight}
            <!-- The membership card leads with a solid strip: what it is + price. -->
            <div
              class="flex items-center justify-between gap-3 bg-primary px-5 py-2.5 text-primary-foreground"
            >
              <span class="text-xs font-extrabold uppercase tracking-[0.1em] rtl:tracking-normal">
                {isCurrent ? t('tiers.yourTier') : t('tiers.recommended')}
              </span>
              {#if fromPerMonth}
                <span class="text-sm font-bold tabular-nums">
                  {t('upgrade.fromPerMonth', { price: fromPerMonth })}
                </span>
              {/if}
            </div>
          {:else if isCurrent}
            <div
              class="absolute start-0 top-0 rounded-ee-lg bg-secondary px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-secondary-foreground"
            >
              {t('tiers.yourTier')}
            </div>
          {/if}

          <div class="space-y-4 p-5 {spotlight ? '' : 'pt-8'}">
            <div class="space-y-1">
              <h3 class="font-display text-lg font-semibold">{tier.name}</h3>
              {#if tier.description}
                <p class="text-sm text-muted-foreground">{tier.description}</p>
              {/if}
            </div>

            <ul class="space-y-2.5 text-sm {spotlight ? 'text-foreground' : ''}">
              <li class="flex items-start gap-2.5">
                {#if tier.monthlyTrafficGb === 0}
                  <InfinityIcon class="mt-0.5 size-4 shrink-0 text-primary" aria-hidden="true" />
                {:else}
                  <Gauge class="mt-0.5 size-4 shrink-0 text-primary" aria-hidden="true" />
                {/if}
                <span class="tabular-nums {spotlight ? 'font-bold' : ''}"
                  >{bandwidthLabel(tier.monthlyTrafficGb)}</span
                >
              </li>
              {#if showDevices}
                <li class="flex items-start gap-2.5">
                  <Check class="mt-0.5 size-4 shrink-0 text-primary" aria-hidden="true" />
                  <span class="tabular-nums">{deviceLabel(tier.deviceLimit)}</span>
                </li>
              {/if}
              {#each tier.features as f, i (i)}
                {@const Icon = resolveTierFeatureIcon(f.iconId)}
                {@const text = tierFeatureText(f)}
                {#if text}
                  <li class="flex items-start gap-2.5">
                    <Icon class="mt-0.5 size-4 shrink-0 text-primary" aria-hidden="true" />
                    <span>{text}</span>
                  </li>
                {/if}
              {/each}
            </ul>

            {#if isMembership && !isCurrent && billingEnabled && onUpgrade}
              <Button size="lg" class="w-full" onclick={onUpgrade}>
                {t('tiers.upgradeCta')}
              </Button>
            {/if}
          </div>
        </div>
      {/each}
    </div>
  {/if}
</section>
