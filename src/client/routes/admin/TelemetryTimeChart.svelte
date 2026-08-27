<script lang="ts">
  import { BarChart } from 'layerchart';
  import { Button } from '@client/components/ui/button';
  import { bucketRows, presentReasons, reasonColor } from '../../lib/telemetryViz';
  import type { AdminTelemetrySummary } from '@shared/contracts/telemetry';

  /**
   * Events over time (the headline telemetry chart): one stacked bar per
   * bucket (hourly on short ranges, daily otherwise), stacked by REASON by
   * default with a toggle to stack by KIND (switch vs report). One value axis,
   * fixed per-reason colors (see lib/telemetryViz), legend on (>= 2 series),
   * LayerChart's crosshair tooltip on by default. The reasons table above the
   * chart is the accessible/table view of the same data.
   */
  interface Props {
    summary: AdminTelemetrySummary;
  }
  let { summary }: Props = $props();

  let stackBy = $state<'reason' | 'kind'>('reason');

  const rows = $derived(bucketRows(summary.buckets, summary.bucketMs ?? 86_400_000));
  const reasons = $derived(presentReasons(summary.buckets));
  const series = $derived(
    stackBy === 'reason'
      ? reasons.map((r) => ({ key: r, label: r, color: reasonColor(r) }))
      : [
          { key: 'switch', label: 'switches', color: 'var(--viz-s1)' },
          { key: 'report', label: 'reports', color: 'var(--viz-s2)' },
        ],
  );
  const hasData = $derived(summary.totals.current > 0);
</script>

<div class="space-y-2">
  <div class="flex items-center justify-between gap-3">
    <p class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Over time</p>
    <div class="flex gap-1">
      <Button
        size="sm"
        variant={stackBy === 'reason' ? 'default' : 'outline'}
        onclick={() => (stackBy = 'reason')}
      >
        By reason
      </Button>
      <Button
        size="sm"
        variant={stackBy === 'kind' ? 'default' : 'outline'}
        onclick={() => (stackBy = 'kind')}
      >
        By kind
      </Button>
    </div>
  </div>
  {#if hasData && series.length > 0}
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
    <p class="text-sm text-muted-foreground">No events in this range.</p>
  {/if}
</div>
