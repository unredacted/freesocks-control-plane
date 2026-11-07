<script lang="ts">
  /**
   * The membership block on /get-account, below the free key panel: a solid
   * header strip (plan name + monthly price), the headline and price, the
   * plan's lines (bandwidth, then Admin → Tiers card features) and one large
   * action that opens the payment form in place. Everything is DB-driven: tier
   * name/limits/lines from /api/v1/config, the price from the billing catalog
   * (the shortest term's per-month, like the plan cards). Callers render it only
   * while billing is on and a membership tier exists; `children` holds what goes
   * under it (the gift-code redeem).
   */
  import type { Snippet } from 'svelte';
  import { Button } from '@client/components/ui/button';
  import Gauge from '@lucide/svelte/icons/gauge';
  import InfinityIcon from '@lucide/svelte/icons/infinity';
  import { configQuery } from '../lib/queries';
  import { t } from '../lib/i18n/index.svelte';
  import { formatMoney } from '../lib/i18n/format';
  import { baselinePerMonth } from '../lib/billing';
  import { freeTier, membershipTier } from '../lib/tiers';
  import { resolveTierFeatureIcon } from '../lib/tierFeatureIcons';
  import { tierFeatureText } from '../lib/tierFeatureCopy';

  interface Props {
    onUpgrade: () => void;
    children?: Snippet;
  }
  let { onUpgrade, children }: Props = $props();

  const config = configQuery();
  let member = $derived(membershipTier(config.data));
  let free = $derived(freeTier(config.data));
  let unlimited = $derived(member?.monthlyTrafficGb === 0);
  let monthlyCents = $derived(baselinePerMonth(config.data?.billing?.durations ?? []));
  let price = $derived(
    monthlyCents !== null
      ? formatMoney(Math.round(monthlyCents), config.data?.billing?.currency ?? 'USD')
      : null,
  );
  let lines = $derived(
    (member?.features ?? [])
      .map((f) => ({ iconId: f.iconId, text: tierFeatureText(f) }))
      .filter((f) => f.text),
  );
</script>

{#if member}
  <section aria-labelledby="spotlight-title" class="shimmer-border overflow-hidden rounded-lg">
    <div
      class="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 bg-primary px-5 py-3 text-primary-foreground sm:px-7"
    >
      <span
        class="font-display text-sm font-extrabold uppercase tracking-[0.04em] rtl:tracking-normal"
      >
        {member.name}
      </span>
      {#if price}
        <span class="text-sm font-bold tabular-nums">
          {t('upgrade.fromPerMonth', { price })}
        </span>
      {/if}
    </div>

    <div class="grid gap-8 p-5 sm:p-7 md:grid-cols-2">
      <div class="space-y-4">
        <h2
          id="spotlight-title"
          class="font-display text-[clamp(26px,3vw,34px)] font-bold leading-[1.08] tracking-[-0.02em] rtl:leading-[1.3] rtl:tracking-normal"
        >
          {unlimited ? t('get.spotlight.titleUnlimited') : t('get.spotlight.title')}
        </h2>
        <p class="leading-relaxed text-body">
          {unlimited ? t('get.spotlight.bodyUnlimited') : t('get.spotlight.body')}
        </p>
        {#if price}
          <p class="flex flex-wrap items-baseline gap-x-2.5 gap-y-1">
            <!-- <bdi>: a currency amount keeps its order inside right-to-left text. -->
            <bdi
              class="font-display text-[clamp(40px,5vw,52px)] font-extrabold leading-none tracking-[-0.03em] text-foreground rtl:tracking-normal"
              >{price}</bdi
            >
            <span class="text-muted-foreground">{t('get.spotlight.priceNote')}</span>
          </p>
        {/if}
      </div>

      <ul class="space-y-3">
        <li class="flex items-center gap-3.5">
          <span
            class="flex size-10 shrink-0 items-center justify-center rounded-sm bg-primary/15 text-primary"
          >
            {#if unlimited}
              <InfinityIcon class="size-5" aria-hidden="true" />
            {:else}
              <Gauge class="size-5" aria-hidden="true" />
            {/if}
          </span>
          <span>
            <strong class="text-foreground">
              {unlimited
                ? t('get.spotlight.unlimited')
                : t('tiers.gbPerMonth', { gb: member.monthlyTrafficGb })}
            </strong>
            {#if unlimited && free && free.monthlyTrafficGb > 0}
              <span class="block text-sm text-muted-foreground">
                {t('get.spotlight.freeCompare', { gb: free.monthlyTrafficGb })}
              </span>
            {/if}
          </span>
        </li>
        {#each lines as line, i (i)}
          {@const Icon = resolveTierFeatureIcon(line.iconId)}
          <li class="flex items-center gap-3.5">
            <span
              class="flex size-10 shrink-0 items-center justify-center rounded-sm bg-primary/15 text-primary"
            >
              <Icon class="size-5" aria-hidden="true" />
            </span>
            <strong class="text-foreground">{line.text}</strong>
          </li>
        {/each}
      </ul>
    </div>

    <div class="flex flex-wrap items-center gap-x-5 gap-y-3 px-5 pb-6 sm:px-7">
      <Button size="lg" class="h-13 px-7 text-lg" onclick={onUpgrade}>
        {t('get.spotlight.cta')}
      </Button>
      <span class="text-[15px] text-muted-foreground">{t('get.spotlight.ctaNote')}</span>
    </div>

    {#if children}
      <div class="border-t border-border/70 px-5 py-4 sm:px-7">
        {@render children()}
      </div>
    {/if}
  </section>
{/if}
