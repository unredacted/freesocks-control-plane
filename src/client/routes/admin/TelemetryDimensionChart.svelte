<script lang="ts">
  import { BarChart } from 'layerchart';
  import { Button } from '@client/components/ui/button';
  import { dimensionRows, dimensionReasons, reasonColor } from '../../lib/telemetryViz';
  import type { AdminTelemetrySummary } from '@shared/contracts/telemetry';

  /**
   * Where the problems cluster: horizontal bars for the top keys of one
   * dimension (location / country / network / mode / backend), stacked by
   * reason with the same fixed per-reason colors as the over-time chart, so
   * "which ASNs, and why" reads in one glance. The dimension picker is the
   * filter row; the list cards below stay as the accessible/table view.
   */
  interface Props {
    summary: AdminTelemetrySummary;
  }
  let { summary }: Props = $props();

  const DIMENSIONS = [
    { id: 'byLocation', label: 'Location' },
    { id: 'byCountry', label: 'Country' },
    { id: 'byAsn', label: 'Network (ASN)' },
    { id: 'byMode', label: 'Mode' },
    { id: 'byBackend', label: 'Backend' },
  ] as const;
  type DimensionId = (typeof DIMENSIONS)[number]['id'];
  let dimension = $state<DimensionId>('byLocation');

  const dimRows = $derived(summary[dimension]);
  const rows = $derived(dimensionRows(dimRows));
  const reasons = $derived(dimensionReasons(dimRows));
  const series = $derived(reasons.map((r) => ({ key: r, label: r, color: reasonColor(r) })));
  // Row height scales with entries so 2 keys don't become 2 giant slabs.
  const chartHeight = $derived(Math.max(120, Math.min(320, 40 * rows.length + 48)));
</script>

<div class="space-y-2">
  <div class="flex flex-wrap items-center justify-between gap-3">
    <p class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
      Where it clusters
    </p>
    <div class="flex flex-wrap gap-1">
      {#each DIMENSIONS as d (d.id)}
        <Button
          size="sm"
          variant={dimension === d.id ? 'default' : 'outline'}
          onclick={() => (dimension = d.id)}
        >
          {d.label}
        </Button>
      {/each}
    </div>
  </div>
  {#if rows.length > 0 && series.length > 0}
    <div class="viz-telemetry w-full" style="height: {chartHeight}px">
      <BarChart
        data={rows}
        y="key"
        orientation="horizontal"
        {series}
        seriesLayout="stack"
        stackPadding={2}
        legend
        props={{ xAxis: { ticks: 4 } }}
      />
    </div>
  {:else}
    <p class="text-sm text-muted-foreground">
      Nothing to chart for this dimension in the selected range.
    </p>
  {/if}
</div>
