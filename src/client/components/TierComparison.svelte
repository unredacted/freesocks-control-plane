<script lang="ts">
  import Check from '@lucide/svelte/icons/check';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { configQuery } from '../lib/queries';
  import { t } from '../lib/i18n/index.svelte';
  import { formatMoney } from '../lib/i18n/format';

  /**
   * Tier comparison cards, rendered ENTIRELY from `/api/v1/config` — name,
   * description, and the bandwidth/device limits are the live DB values, so
   * Admin → Tiers edits propagate here (and to every other view that renders
   * this) with no hardcoded copy to drift. The membership tier (the one whose
   * slug matches `billing.tierSlug`) shows its monthly price (the shortest term's
   * per-month) + an Upgrade CTA when billing is enabled and the parent supplies
   * `onUpgrade`. Longer-term discounts are shown in the upgrade panel, not here.
   */
  interface Props {
    currentTierSlug: string;
    /** Called when the membership-card CTA is clicked (parent scrolls to / opens the panel). */
    onUpgrade?: () => void;
  }
  let { currentTierSlug, onUpgrade }: Props = $props();

  const config = configQuery();
  let tiers = $derived(config.data?.tiers ?? []);
  let billing = $derived(config.data?.billing);
  let billingEnabled = $derived(billing?.enabled ?? false);
  let membershipSlug = $derived(billing?.tierSlug ?? 'member');

  // The headline monthly price = the SHORTEST term's per-month (e.g. the 1-month
  // plan at $5/mo), NOT the cheapest amortized annual ($4.17/mo) — that read as a
  // pricing bug. Longer-term discounts live in the upgrade panel instead.
  let monthlyCents = $derived.by(() => {
    const ds = (billing?.durations ?? []).filter((d) => d.months > 0);
    if (ds.length === 0) return null;
    const shortest = ds.reduce((a, b) => (b.months < a.months ? b : a));
    return shortest.amountCents / shortest.months;
  });
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
  <div>
    <h2 class="font-display text-xl font-bold tracking-tight">{t('tiers.title')}</h2>
    <p class="text-sm text-muted-foreground">{t('tiers.subtitle')}</p>
  </div>

  {#if config.isPending}
    <div class="grid gap-3 sm:grid-cols-2">
      <Skeleton class="h-48 w-full" />
      <Skeleton class="h-48 w-full" />
    </div>
  {:else}
    <div class="grid gap-3 sm:grid-cols-2">
      {#each tiers as tier (tier.slug)}
        {@const isCurrent = tier.slug === currentTierSlug}
        {@const isMembership = tier.slug === membershipSlug}
        <div
          class="relative space-y-4 overflow-hidden rounded-xl border bg-card p-5 {isCurrent
            ? 'border-primary/30 ring-1 ring-primary/30'
            : 'border-border'}"
        >
          {#if isCurrent}
            <div
              class="absolute start-0 top-0 rounded-ee-lg bg-secondary px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-secondary-foreground"
            >
              {t('tiers.yourTier')}
            </div>
          {/if}

          <div class="space-y-1 pt-3">
            <h3 class="font-display text-lg font-semibold">{tier.name}</h3>
            {#if isMembership && billingEnabled && fromPerMonth}
              <p class="text-sm tabular-nums text-muted-foreground">
                {t('upgrade.perMonth', { price: fromPerMonth })}
              </p>
            {/if}
            {#if tier.description}
              <p class="text-sm text-muted-foreground">{tier.description}</p>
            {/if}
          </div>

          <ul class="space-y-2 text-sm">
            <li class="flex items-start gap-2">
              <Check class="mt-0.5 size-4 shrink-0 text-primary" />
              <span class="tabular-nums">{bandwidthLabel(tier.monthlyTrafficGb)}</span>
            </li>
            <li class="flex items-start gap-2">
              <Check class="mt-0.5 size-4 shrink-0 text-primary" />
              <span class="tabular-nums">{deviceLabel(tier.deviceLimit)}</span>
            </li>
            <li class="flex items-start gap-2">
              <Check class="mt-0.5 size-4 shrink-0 text-primary" />
              <span class="text-muted-foreground">{t('tiers.mirrors')}</span>
            </li>
          </ul>

          {#if isMembership && !isCurrent && billingEnabled && onUpgrade}
            <Button variant="default" class="w-full" size="sm" onclick={onUpgrade}>
              {t('tiers.upgradeCta')}
            </Button>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</section>
