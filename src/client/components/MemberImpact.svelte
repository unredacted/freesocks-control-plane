<script lang="ts">
  import Heart from '@lucide/svelte/icons/heart';
  import { t } from '../lib/i18n/index.svelte';
  import { formatMoney } from '../lib/i18n/format';
  import { configQuery, accountQuery } from '../lib/queries';
  import { impactChartSeries } from '../lib/impact';
  import DitherChart from './DitherChart.svelte';

  /**
   * Donation-impact panel: what the community's donations are doing for free
   * users right now (bonus GB live this month, free accounts it reaches, and
   * the per-month history as a dithered bar chart), plus - for donors - their
   * own contribution. The nonprofit framing card grew into this once the
   * impact numbers became available from publicConfig (`billing.donation`).
   * Falls back to the plain framing when donations are disabled or there's no
   * impact data yet, so the card never renders empty charts.
   */
  const config = configQuery();
  const account = accountQuery();

  const donation = $derived(config.data?.billing?.donation);
  const history = $derived(donation?.history ?? []);
  // Renders whenever donations are live (a zero month is honest data - the
  // empty note explains it); the chart falls back to a flat zero baseline.
  const showImpact = $derived(!!config.data?.billing?.enabled && !!donation?.enabled);
  const chartSeries = $derived(impactChartSeries(history));
  const user = $derived(account.data?.user);
  const isDonor = $derived(!!user?.donorSince && (user?.donatedCentsTotal ?? 0) > 0);
  // Personal display framing: the member's lifetime giving converted at the
  // current rate - an approximation for copy, not an accounting figure.
  const personalGb = $derived(
    Math.round(((user?.donatedCentsTotal ?? 0) / 100) * (donation?.bonusGbPerUsd ?? 0) * 10) / 10,
  );
  const fmtGb = (gb: number) => (Number.isInteger(gb) ? String(gb) : gb.toFixed(1));
</script>

<section class="rounded-xl border border-border bg-card p-6 md:p-8 space-y-5">
  <div class="flex items-start gap-3">
    <div class="rounded-full bg-primary/10 p-2 text-primary shrink-0" aria-hidden="true">
      <Heart class="size-5" />
    </div>
    <div>
      <h2 class="text-xl font-display font-bold tracking-tight">
        {showImpact ? t('impact.collectiveTitle') : t('impact.title')}
      </h2>
      <p class="text-sm text-muted-foreground mt-1 max-w-xl leading-relaxed">
        {showImpact ? t('impact.collectiveBody') : t('impact.body')}
      </p>
    </div>
  </div>

  {#if showImpact && donation}
    <!-- Collective stats: the accessible signal for the decorative chart. -->
    <div class="grid grid-cols-2 gap-3">
      <div class="rounded-lg border border-border bg-background/60 p-4">
        <div
          class="text-2xl font-display font-bold tabular-nums text-amber-600 dark:text-amber-300"
        >
          +{fmtGb(donation.currentBonusGb)}
        </div>
        <div class="text-xs font-medium mt-0.5">{t('impact.bonusThisMonth')}</div>
        <div class="text-xs text-muted-foreground mt-0.5">{t('impact.bonusThisMonthDetail')}</div>
      </div>
      <div class="rounded-lg border border-border bg-background/60 p-4">
        <div class="text-2xl font-display font-bold tabular-nums">
          {donation.freeUsersHelped.toLocaleString()}
        </div>
        <div class="text-xs font-medium mt-0.5">{t('impact.usersHelped')}</div>
        <div class="text-xs text-muted-foreground mt-0.5">{t('impact.usersHelpedDetail')}</div>
      </div>
    </div>

    <div>
      <div class="text-xs font-medium text-muted-foreground mb-2">
        {t('impact.historyTitle')}
      </div>
      <DitherChart
        values={chartSeries.map((h) => h.bonusGb)}
        labels={chartSeries.map((h) => h.month)}
        variant="bars"
        height={88}
        ariaLabel={t('impact.chartAria', { n: chartSeries.length })}
      />
      {#if history.length === 0}
        <p class="mt-2 text-xs text-muted-foreground">{t('impact.empty')}</p>
      {/if}
    </div>

    {#if isDonor && user}
      <div class="donation-sheen rounded-lg border border-amber-500/40 bg-amber-500/5 p-4">
        <div class="text-xs font-medium text-amber-700 dark:text-amber-300">
          {t('impact.yourContribution')}
        </div>
        <div class="text-sm mt-1">
          {t('impact.yourGiven', {
            amount: formatMoney(user.donatedCentsTotal, config.data?.billing?.currency ?? 'USD'),
          })}
          <span class="text-muted-foreground">
            {t('impact.yourCount', { count: user.donationCount })}</span
          >
        </div>
        {#if personalGb > 0}
          <div class="text-xs text-muted-foreground mt-0.5">
            {t('impact.yourGb', { gb: fmtGb(personalGb) })}
          </div>
        {/if}
      </div>
    {/if}
    <!-- Only in-app donations feed the counter; direct nonprofit gifts don't. -->
    <p class="text-xs text-muted-foreground leading-relaxed">
      {t('impact.externalNote')}
    </p>
  {/if}

  <div class="pt-1 flex flex-wrap gap-3">
    <a href="https://unredacted.org/donate" target="_blank" rel="noopener noreferrer">
      <span
        class="inline-flex items-center gap-1.5 text-sm underline hover:text-foreground text-muted-foreground"
      >
        {t('renew.donate')}
      </span>
    </a>
    <a href="https://unredacted.org" target="_blank" rel="noopener noreferrer">
      <span
        class="inline-flex items-center gap-1.5 text-sm underline hover:text-foreground text-muted-foreground"
      >
        {t('impact.aboutUnredacted')}
      </span>
    </a>
  </div>
</section>
