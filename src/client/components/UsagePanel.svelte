<script lang="ts">
  import Sparkline from './Sparkline.svelte';
  import StatBlock from './StatBlock.svelte';
  import { formatBytes, daysUntil } from '../lib/utils';
  import { formatDate } from '../lib/i18n/format';
  import { t } from '../lib/i18n/index.svelte';

  /**
   * Usage & validity card: traffic (bar + reset hint + trend sparkline) and
   * expiry/activity, extracted from SubscriptionHero in the 2026-08 unclutter
   * pass so the pass carries only the key itself and this card owns the
   * numbers. Same props the hero used to take for its meta zone.
   */
  interface Props {
    trafficLimitBytes: number | null;
    trafficUsedBytes: number;
    expiresAt: string | null;
    /** Free-tier key: the expiry stat becomes activity-framed ("Active while
     *  you use it") — free keys never expire on a calendar; only accounts idle
     *  for `idleDays` are paused. Ignores `expiresAt` entirely (keys issued
     *  before the no-expiry cutover may still carry a stale backend date). */
    freeTier?: boolean;
    /** The idle window (publicConfig.freeTierDays) for the free-key subline. */
    idleDays?: number;
    /** Traffic reset cadence + last-reset anchor → the "resets in N days" hint. */
    resetStrategy?: 'NO_RESET' | 'DAY' | 'WEEK' | 'MONTH';
    lastResetAt?: string;
    /** Aggregate usage trend (bytes per bucket) + period total. Optional:
     *  omitted at sign-up (no data yet) and for backends without usage history. */
    usagePoints?: number[];
    usageTotal?: number;
  }
  let {
    trafficLimitBytes,
    trafficUsedBytes,
    expiresAt,
    freeTier = false,
    idleDays = 90,
    resetStrategy,
    lastResetAt,
    usagePoints,
    usageTotal,
  }: Props = $props();

  // Traffic percentage, only meaningful when there's a limit.
  let usagePct = $derived(
    trafficLimitBytes ? Math.min(100, (trafficUsedBytes / trafficLimitBytes) * 100) : 0,
  );
  let usageColor = $derived(
    usagePct >= 90 ? 'bg-destructive' : usagePct >= 70 ? 'bg-amber-500' : 'bg-primary',
  );

  // Next traffic reset from the cadence + last-reset anchor (null for NO_RESET / no anchor).
  let nextResetDays = $derived.by(() => {
    if (!lastResetAt || !resetStrategy || resetStrategy === 'NO_RESET') return null;
    const base = new Date(lastResetAt);
    if (Number.isNaN(base.getTime())) return null;
    const next = new Date(base);
    if (resetStrategy === 'MONTH') next.setMonth(next.getMonth() + 1);
    else if (resetStrategy === 'WEEK') next.setDate(next.getDate() + 7);
    else next.setDate(next.getDate() + 1);
    return daysUntil(next);
  });

  // Expiry: convert + classify (so we can hint when it's close).
  let expiryDate = $derived(expiresAt ? new Date(expiresAt) : null);
  let daysLeft = $derived(daysUntil(expiresAt));
  // Amber inside the last week; '' otherwise (each line picks its own calm color).
  let expiryUrgency = $derived(
    daysLeft !== null && daysLeft <= 7 ? 'text-amber-700 dark:text-amber-400' : '',
  );
</script>

<section class="panel space-y-5">
  <h2 class="text-xl font-bold leading-tight">{t('usage.panelTitle')}</h2>
  <div class="grid gap-7 sm:grid-cols-2">
    <StatBlock label={t('hero.traffic')}>
      {#if trafficLimitBytes !== null}
        <p
          class="font-display text-[30px] font-bold leading-tight tracking-[-0.02em] text-foreground tabular-nums rtl:tracking-normal"
        >
          <bdi>{formatBytes(trafficUsedBytes)}</bdi>
          <span class="font-sans text-[17px] font-normal tracking-normal text-muted-foreground"
            >/ <bdi>{formatBytes(trafficLimitBytes)}</bdi></span
          >
        </p>
        <div class="h-2.5 overflow-hidden border border-border/70 bg-well" aria-hidden="true">
          <div
            class="h-full {usageColor} transition-all duration-500"
            style="width: {usagePct}%"
          ></div>
        </div>
        <p class="text-[15px] tabular-nums">
          {usagePct >= 90
            ? t('hero.nearlyOut', {
                amount: formatBytes(Math.max(0, trafficLimitBytes - trafficUsedBytes)),
              })
            : t('hero.leftThisPeriod', {
                amount: formatBytes(Math.max(0, trafficLimitBytes - trafficUsedBytes)),
              })}
          {#if nextResetDays !== null && nextResetDays >= 0}
            {t('hero.resetsInDays', { count: nextResetDays })}
          {/if}
        </p>
      {:else}
        <p
          class="font-display text-[30px] font-bold leading-tight tracking-[-0.02em] text-foreground rtl:tracking-normal"
        >
          {t('hero.unlimited')}
        </p>
        <p class="text-[15px] tabular-nums">
          {t('hero.usedSoFar', { amount: formatBytes(trafficUsedBytes) })}
        </p>
      {/if}

      <!-- Usage trend, shown by default. A quiet/new key draws a flat baseline
           (not hidden). Absent only when there's no usage data at all. -->
      {#if usagePoints && usagePoints.length > 0}
        <div class="space-y-1 pt-2">
          <div class="text-primary">
            <Sparkline points={usagePoints} class="h-10 w-full" />
          </div>
          {#if usageTotal !== undefined}
            <p class="text-sm text-muted-foreground tabular-nums">
              {t('usage.total', { amount: formatBytes(usageTotal) })}
            </p>
          {/if}
        </div>
      {/if}
    </StatBlock>

    {#if freeTier}
      <!-- Free keys have no calendar expiry (the panel carries the no-expiry
           sentinel; the usage-based idle sweep governs) — frame the stat
           around activity instead of a date. -->
      <StatBlock label={t('hero.validityLabel')}>
        <p class="font-display text-[22px] font-bold leading-snug text-foreground">
          {t('hero.staysActive')}
        </p>
        <p class="text-[15px] text-muted-foreground">
          {t('hero.idleNote', { days: idleDays })}
        </p>
      </StatBlock>
    {:else}
      <StatBlock label={t('hero.expires')}>
        {#if expiryDate}
          <p
            class="font-display text-[22px] font-bold leading-snug tabular-nums {expiryUrgency ||
              'text-foreground'}"
          >
            {formatDate(expiryDate)}
          </p>
        {:else}
          <p class="font-display text-[22px] font-bold leading-snug text-foreground">
            {t('hero.noExpiry')}
          </p>
        {/if}
        {#if daysLeft !== null}
          <p class="text-[15px] tabular-nums {expiryUrgency || 'text-muted-foreground'}">
            {daysLeft < 0
              ? t('hero.expiredDaysAgo', { count: -daysLeft })
              : daysLeft === 0
                ? t('hero.expiresToday')
                : t('hero.daysRemaining', { count: daysLeft })}
          </p>
        {/if}
      </StatBlock>
    {/if}
  </div>
</section>
