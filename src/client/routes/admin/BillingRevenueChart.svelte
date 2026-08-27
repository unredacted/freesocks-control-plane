<script lang="ts">
  import { BarChart } from 'layerchart';
  import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
  } from '@client/components/ui/card';
  import { Skeleton } from '@client/components/ui/skeleton';
  import InlineError from '../../components/InlineError.svelte';
  import AdminRangePicker from './AdminRangePicker.svelte';
  import { apiErrorMessage } from '../../lib/errors';
  import { formatMoney } from '../../lib/i18n/format';
  import { adminBillingRevenueQuery, type TelemetryRange } from '../../lib/queries';
  import 'layerchart/core.css';

  /**
   * Revenue over time (Admin → Billing): one stacked bar per bucket (hourly on
   * short ranges, daily otherwise) split into the three income kinds. Fixed
   * palette slots (memberships s1 / gifts s5 / donations s4 - donation gold),
   * one money axis, legend + tooltips. Totals beside the chart carry the
   * previous-range compare; the orders list below stays the per-order view.
   */
  let range = $state<TelemetryRange>({ kind: 'window', windowMs: 30 * 86_400_000 });
  const revenue = adminBillingRevenueQuery(() => range);

  const SERIES = [
    { key: 'membershipCents', label: 'memberships', color: 'var(--viz-s1)' },
    { key: 'giftCents', label: 'gift codes', color: 'var(--viz-s5)' },
    { key: 'donationCents', label: 'donations', color: 'var(--viz-s4)' },
  ];

  const rows = $derived.by(() => {
    const d = revenue.data;
    if (!d) return [];
    const hourly = d.bucketMs < 86_400_000;
    return d.buckets.map((b) => ({
      label: new Date(b.start).toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        ...(hourly ? { hour: 'numeric' } : {}),
      }),
      membershipCents: b.membershipCents,
      giftCents: b.giftCents,
      donationCents: b.donationCents,
    }));
  });
  const money = (cents: number) => formatMoney(cents, revenue.data?.currency ?? 'USD');
  const fmtDay = (ms: number) =>
    new Date(ms).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
</script>

<Card>
  <CardHeader>
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div>
        <CardTitle class="text-base">Revenue</CardTitle>
        <CardDescription>
          Paid orders by settle time, split into memberships, gift codes, and donations (a donation
          riding a membership counts as a donation).
        </CardDescription>
      </div>
      <AdminRangePicker bind:range />
    </div>
  </CardHeader>
  <CardContent class="space-y-4 text-sm">
    {#if revenue.isPending}
      <Skeleton class="h-40 w-full" />
    {:else if revenue.isError}
      <InlineError message={apiErrorMessage(revenue.error)} />
    {:else if revenue.data}
      {@const r = revenue.data}
      <p class="text-xs text-muted-foreground">
        Covering {fmtDay(r.sinceMs)} to {fmtDay(r.untilMs)} (compare = the equal range before it).
      </p>
      <div class="grid grid-cols-2 gap-3 sm:grid-cols-5">
        <div class="rounded-lg border border-border p-3">
          <div class="text-xl font-display font-bold tabular-nums">
            {money(r.totals.totalCents)}
          </div>
          <div class="text-xs text-muted-foreground">
            total (prev: {money(r.totals.previousTotalCents)})
          </div>
        </div>
        <div class="rounded-lg border border-border p-3">
          <div class="text-xl font-display font-bold tabular-nums">
            {money(r.totals.membershipCents)}
          </div>
          <div class="text-xs text-muted-foreground">memberships</div>
        </div>
        <div class="rounded-lg border border-border p-3">
          <div class="text-xl font-display font-bold tabular-nums">
            {money(r.totals.giftCents)}
          </div>
          <div class="text-xs text-muted-foreground">gift codes</div>
        </div>
        <div class="rounded-lg border border-border p-3">
          <div class="text-xl font-display font-bold tabular-nums">
            {money(r.totals.donationCents)}
          </div>
          <div class="text-xs text-muted-foreground">donations</div>
        </div>
        <div class="rounded-lg border border-border p-3">
          <div class="text-xl font-display font-bold tabular-nums">{r.totals.orders}</div>
          <div class="text-xs text-muted-foreground">paid orders</div>
        </div>
      </div>
      {#if r.totals.totalCents > 0}
        <div class="viz-telemetry h-64 w-full">
          <BarChart
            data={rows}
            x="label"
            series={SERIES}
            seriesLayout="stack"
            stackPadding={2}
            legend
            props={{
              xAxis: { ticks: 8 },
              yAxis: { ticks: 4, format: (v: number) => money(v) },
            }}
          />
        </div>
      {:else}
        <p class="text-muted-foreground">No paid orders in this range.</p>
      {/if}
      {#if r.otherCurrencyOrders > 0}
        <p class="text-xs text-amber-600">
          {r.otherCurrencyOrders} paid order{r.otherCurrencyOrders === 1 ? '' : 's'} in this range settled
          in a different currency than the current {r.currency} setting and are not included in these
          sums (mixed currencies never share a total).
        </p>
      {/if}
      {#if r.truncated}
        <p class="text-xs text-amber-600">
          This range holds more paid orders than one computation reads (20k). Narrow the range for
          exact numbers.
        </p>
      {/if}
    {/if}
  </CardContent>
</Card>
