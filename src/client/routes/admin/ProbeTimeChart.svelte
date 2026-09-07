<script lang="ts">
  import { BarChart } from 'layerchart';
  import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
  } from '@client/components/ui/card';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import InlineError from '../../components/InlineError.svelte';
  import AdminRangePicker from './AdminRangePicker.svelte';
  import { apiErrorMessage } from '../../lib/errors';
  import { adminProbeSummaryQuery, type TelemetryRange } from '../../lib/queries';
  import { VIZ_PALETTE } from '../../lib/telemetryViz';

  /**
   * Probe outcomes over time (Telemetry → Probes): one stacked bar per bucket
   * (hourly on short ranges, daily otherwise). "Failing vantages by country"
   * is the headline view: a country whose bar grows is where our addresses
   * stopped answering. The toggle shows ok vs failing vantages instead. Colors
   * are assigned per country in a fixed order (the same `--viz-sN` slots the
   * other admin charts use), so a country keeps its hue across ranges.
   */
  let range = $state<TelemetryRange>({ kind: 'window', windowMs: 7 * 86_400_000 });
  const summary = adminProbeSummaryQuery(() => range);
  let mode = $state<'country' | 'outcome'>('country');

  const countries = $derived.by(() => {
    const d = summary.data;
    if (!d) return [] as string[];
    // Configured order = alphabetical here; the internal check ('XX') stays last.
    return d.byCountry
      .map((c) => c.country)
      .filter((c) => c !== 'XX')
      .concat(d.byCountry.some((c) => c.country === 'XX') ? ['XX'] : []);
  });
  const rows = $derived.by(() => {
    const d = summary.data;
    if (!d) return [];
    const hourly = d.bucketMs < 86_400_000;
    return d.buckets.map((b) => ({
      label: new Date(b.start).toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        ...(hourly ? { hour: 'numeric' } : {}),
      }),
      ok: b.ok,
      fail: b.fail,
      ...Object.fromEntries(countries.map((c) => [c, b.byCountry[c]?.fail ?? 0])),
    }));
  });
  const series = $derived(
    mode === 'country'
      ? countries.slice(0, VIZ_PALETTE.length).map((c, i) => ({
          key: c,
          label: c === 'XX' ? 'FCP (internal)' : c,
          color: `var(--viz-s${i + 1})`,
        }))
      : [
          { key: 'fail', label: 'failing vantages', color: 'var(--viz-s8)' },
          { key: 'ok', label: 'ok vantages', color: 'var(--viz-s3)' },
        ],
  );
  const fmtDay = (ms: number) =>
    new Date(ms).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  const pct = (fail: number, ok: number) =>
    fail + ok === 0 ? '·' : `${Math.round((fail / (fail + ok)) * 100)}%`;
</script>

<Card>
  <CardHeader>
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div>
        <CardTitle class="text-base">Probe outcomes</CardTitle>
        <CardDescription>
          Vantage results from finished runs, by request time. A country whose failing bar grows is
          where our addresses stopped answering; "FCP" is the internal connect check.
        </CardDescription>
      </div>
      <div class="flex flex-wrap items-center gap-2">
        <div class="flex gap-1">
          <Button
            size="sm"
            variant={mode === 'country' ? 'default' : 'outline'}
            onclick={() => (mode = 'country')}>Failing by country</Button
          >
          <Button
            size="sm"
            variant={mode === 'outcome' ? 'default' : 'outline'}
            onclick={() => (mode = 'outcome')}>Ok vs failing</Button
          >
        </div>
        <AdminRangePicker bind:range />
      </div>
    </div>
  </CardHeader>
  <CardContent class="space-y-4 text-sm">
    {#if summary.isPending}
      <Skeleton class="h-40 w-full" />
    {:else if summary.isError}
      <InlineError message={apiErrorMessage(summary.error)} />
    {:else if summary.data}
      {@const s = summary.data}
      <p class="text-xs text-muted-foreground">
        Covering {fmtDay(s.sinceMs)} to {fmtDay(s.untilMs)}.
      </p>
      <div class="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div class="rounded-lg border border-border p-3">
          <div class="text-2xl font-display font-bold tabular-nums">{s.totals.runs}</div>
          <div class="text-xs text-muted-foreground">finished runs</div>
        </div>
        <div class="rounded-lg border border-border p-3">
          <div class="text-2xl font-display font-bold tabular-nums">{s.totals.ok}</div>
          <div class="text-xs text-muted-foreground">ok vantages</div>
        </div>
        <div class="rounded-lg border border-border p-3">
          <div class="text-2xl font-display font-bold tabular-nums">{s.totals.fail}</div>
          <div class="text-xs text-muted-foreground">failing vantages</div>
        </div>
        <div class="rounded-lg border border-border p-3">
          <div class="text-2xl font-display font-bold tabular-nums">
            {pct(s.totals.fail, s.totals.ok)}
          </div>
          <div class="text-xs text-muted-foreground">failing share</div>
        </div>
      </div>
      {#if s.totals.runs > 0 && series.length > 0}
        <div class="viz-telemetry h-64 w-full">
          <BarChart
            data={rows}
            x="label"
            {series}
            seriesLayout="stack"
            stackPadding={2}
            legend
            props={{ xAxis: { ticks: 8 }, yAxis: { ticks: 4 } }}
          />
        </div>
      {:else}
        <p class="text-muted-foreground">No finished probe runs in this range.</p>
      {/if}
      {#if s.byCountry.length > 0}
        <div class="grid gap-4 md:grid-cols-2">
          <div class="rounded-lg border border-border p-3">
            <p class="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              By country
            </p>
            <ul class="space-y-1">
              {#each s.byCountry as c (c.country)}
                <li class="flex items-baseline justify-between gap-2 text-sm">
                  <span class="font-medium"
                    >{c.country === 'XX' ? 'FCP (internal)' : c.country}</span
                  >
                  <span class="shrink-0 text-xs text-muted-foreground tabular-nums">
                    {c.fail} failing / {c.ok} ok · {pct(c.fail, c.ok)}
                  </span>
                </li>
              {/each}
            </ul>
          </div>
          <div class="rounded-lg border border-border p-3">
            <p class="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              By source
            </p>
            <ul class="space-y-1">
              {#each s.bySource as c (c.source)}
                <li class="flex items-baseline justify-between gap-2 text-sm">
                  <span class="font-medium">{c.source}</span>
                  <span class="shrink-0 text-xs text-muted-foreground tabular-nums">
                    {c.runs} runs · {c.fail} failing / {c.ok} ok
                  </span>
                </li>
              {/each}
            </ul>
          </div>
        </div>
      {/if}
      {#if s.truncated}
        <p class="text-xs text-amber-600">
          The range holds more runs than one summary reads (5k). Narrow the range for exact numbers.
        </p>
      {/if}
    {/if}
  </CardContent>
</Card>
