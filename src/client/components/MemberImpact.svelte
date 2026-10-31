<script lang="ts">
  import { t } from '../lib/i18n/index.svelte';
  import { formatMoney, formatDate } from '../lib/i18n/format';
  import { configQuery, accountQuery, meQuery } from '../lib/queries';
  import { dailyImpactSeries, dailyImpactBounds, giftMarks, niceCeil } from '../lib/impact';
  import DitherChart from './DitherChart.svelte';

  /**
   * Donation-impact backend: what the community's donations are doing for free
   * users right now (bonus GB live this month, free accounts it reaches, and
   * the month-to-date daily staircase as a dithered chart), plus - for donors - their
   * own contribution. The nonprofit framing card grew into this once the
   * impact numbers became available from publicConfig (`billing.donation`).
   * Falls back to the plain framing when donations are disabled or there's no
   * impact data yet, so the card never renders empty charts.
   */
  const config = configQuery();
  // Gated on a session existing: the backend also renders on the public /donate
  // page, where an unconditional account fetch would just 401 every mount.
  const me = meQuery();
  const account = accountQuery(() => !!me.data?.authenticated);

  const donation = $derived(config.data?.billing?.donation);
  // Renders whenever donations are live (a zero month is honest data - the
  // empty note explains it); the chart falls back to a flat zero baseline.
  const showImpact = $derived(!!config.data?.billing?.enabled && !!donation?.enabled);
  // Cumulative staircase across the whole month (one point per day). The
  // per-month ledger stays recorded server-side; a single live month made the old
  // month-by-month bars degenerate to one full-width bar.
  const dailyValues = $derived(dailyImpactSeries(donation?.currentMonthDaily ?? []));
  const dailyEmpty = $derived(!dailyValues.some((v) => v > 0));
  // Round headroom above the month's total, so the last step reads as a step
  // rather than a full-height block pinned to the top edge.
  const dailyMax = $derived(niceCeil(Math.max(...dailyValues, 0)));
  // How long a gift funds the pool. Operator-tunable (1-365), so the copy must
  // read it rather than promise a fixed 30 days.
  const windowDays = $derived(donation?.bonusWindowDays ?? 30);
  // UTC, matching the series: the buckets are UTC days, so formatting the
  // endcaps in local time renders "Jul 31 - Aug 30" for an August series.
  const dayLabel = (d: Date) => formatDate(d, { month: 'short', day: 'numeric', timeZone: 'UTC' });
  const dailyLabels = $derived(dailyImpactBounds().map(dayLabel));
  // Live gifts (server projection): power the chart's donation-day marks and
  // the per-gift "lasts until" rows below it.
  const gifts = $derived(donation?.recentGifts ?? []);
  const marks = $derived(giftMarks(gifts).map((m) => ({ frac: m.frac, label: dayLabel(m.date) })));
  // A gift stops funding the pool AT `expiresAt` (a UTC midnight), so the last
  // fully-funded day is the one before it.
  const giftUntil = (expiresAt: number) => dayLabel(new Date(expiresAt - 1));
  const user = $derived(account.data?.user);
  const isDonor = $derived(!!user?.donorSince && (user?.donatedCentsTotal ?? 0) > 0);
  // Personal display framing: the member's lifetime giving in GB, computed
  // server-side at the current rate (the raw rate is never shipped publicly).
  const personalGb = $derived(Math.round((user?.donatedGbTotal ?? 0) * 10) / 10);
  const fmtGb = (gb: number) => (Number.isInteger(gb) ? String(gb) : gb.toFixed(1));
</script>

<section class="panel space-y-6">
  <div>
    <h2 class="text-xl font-bold leading-tight">
      {showImpact ? t('impact.collectiveTitle') : t('impact.title')}
    </h2>
    <p class="mt-1.5 max-w-xl text-body">
      {showImpact ? t('impact.collectiveBody', { days: windowDays }) : t('impact.body')}
    </p>
  </div>

  {#if showImpact && donation}
    <!-- Collective stats: the accessible signal for the decorative chart. -->
    <div class="grid gap-6 sm:grid-cols-2">
      <div class="border-t-2 border-border pt-3">
        <div
          class="font-display text-[34px] font-bold leading-none tracking-[-0.02em] text-primary tabular-nums rtl:tracking-normal"
        >
          +{fmtGb(donation.currentBonusGb)}
        </div>
        <div class="mt-2 font-bold text-foreground">{t('impact.bonusThisMonth')}</div>
        <div class="text-sm text-muted-foreground">{t('impact.bonusThisMonthDetail')}</div>
      </div>
      <div class="border-t-2 border-border pt-3">
        <div
          class="font-display text-[34px] font-bold leading-none tracking-[-0.02em] text-foreground tabular-nums rtl:tracking-normal"
        >
          {donation.freeUsersHelped.toLocaleString()}
        </div>
        <div class="mt-2 font-bold text-foreground">{t('impact.usersHelped')}</div>
        <div class="text-sm text-muted-foreground">{t('impact.usersHelpedDetail')}</div>
      </div>
    </div>

    <div>
      <div class="mb-2 text-sm text-muted-foreground">
        {t('impact.dailyTitle')}
      </div>
      <DitherChart
        values={dailyValues}
        labels={dailyLabels}
        {marks}
        variant="area"
        step
        max={dailyMax}
        height={88}
        ariaLabel={t('impact.dailyChartAria')}
      />
      {#if dailyEmpty}
        <p class="mt-2 text-sm text-muted-foreground">{t('impact.empty')}</p>
      {/if}
    </div>

    <!-- The gifts currently funding the pool: when each landed, what it added,
         and the day it stops - the concrete answer to "how long does a
         donation last?". -->
    {#if gifts.length > 0}
      <div>
        <div class="mb-1 text-sm text-muted-foreground">
          {t('impact.giftsTitle')}
        </div>
        <ul class="divide-y divide-border/70 border-y border-border/70">
          {#each gifts.slice().reverse() as g (g.day + ':' + g.expiresAt)}
            <li
              class="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5 py-2.5 text-[15px]"
            >
              <span class="tabular-nums">{dayLabel(new Date(`${g.day}T00:00:00Z`))}</span>
              <span class="font-bold tabular-nums text-primary">
                <bdi>+{fmtGb(Math.round(g.gb * 10) / 10)} GB</bdi>
              </span>
              <span class="text-sm text-muted-foreground tabular-nums">
                {t('impact.giftActiveUntil', { date: giftUntil(g.expiresAt) })}
              </span>
            </li>
          {/each}
        </ul>
      </div>
    {/if}

    {#if isDonor && user}
      <div class="rounded-sm border border-border/70 bg-well p-4">
        <div class="text-sm font-bold text-foreground">
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
          <div class="mt-0.5 text-sm text-muted-foreground">
            {t('impact.yourGb', { gb: fmtGb(personalGb) })}
          </div>
        {/if}
      </div>
    {/if}
    <!-- Only in-app donations feed the counter; direct nonprofit gifts don't. -->
    <p class="text-sm text-muted-foreground">
      {t('impact.externalNote')}
    </p>
  {/if}

  <!-- No external donate link here: giving happens in-app (the donate card
       right below this panel) so gifts actually feed the bandwidth pool. -->
  <p class="text-[15px]">
    <a
      class="link-brand text-foreground"
      href="https://unredacted.org"
      target="_blank"
      rel="noopener noreferrer">{t('impact.aboutUnredacted')}</a
    >
  </p>
</section>
