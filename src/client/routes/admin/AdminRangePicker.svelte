<script lang="ts">
  import { Button } from '@client/components/ui/button';
  import { Input } from '@client/components/ui/input';
  import { toast } from 'svelte-sonner';
  import type { TelemetryRange } from '../../lib/queries';

  /**
   * The shared admin chart range control: trailing-window presets plus a
   * custom from/to date range (inclusive days). Used by Admin → Telemetry and
   * Admin → Billing so every chart page ranges identically. The server clamps
   * the span; the retention/scan caps bound how far back data exists.
   */
  const DAY = 86_400_000;
  const PRESETS = [
    { label: '24 hours', ms: DAY },
    { label: '7 days', ms: 7 * DAY },
    { label: '30 days', ms: 30 * DAY },
    { label: '90 days', ms: 90 * DAY },
  ];

  interface Props {
    range: TelemetryRange;
  }
  let { range = $bindable() }: Props = $props();

  let customFrom = $state('');
  let customTo = $state('');
  function applyCustomRange() {
    // Local dates, inclusive: "to" runs to the END of the picked day so
    // today's events are included.
    const from = new Date(`${customFrom}T00:00:00`).getTime();
    const to = new Date(`${customTo}T23:59:59.999`).getTime();
    if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from) {
      toast.error('Pick a valid date range (from before to)');
      return;
    }
    range = { kind: 'range', fromMs: from, toMs: to };
  }
</script>

<div class="space-y-2">
  <div class="flex flex-wrap gap-1">
    {#each PRESETS as w (w.ms)}
      <Button
        size="sm"
        variant={range.kind === 'window' && range.windowMs === w.ms ? 'default' : 'outline'}
        onclick={() => (range = { kind: 'window', windowMs: w.ms })}
      >
        {w.label}
      </Button>
    {/each}
  </div>
  <div class="flex flex-wrap items-center gap-1.5">
    <Input
      type="date"
      class="h-8 w-36 text-xs"
      value={customFrom}
      oninput={(e) => (customFrom = (e.target as HTMLInputElement).value)}
    />
    <span class="text-xs text-muted-foreground">to</span>
    <Input
      type="date"
      class="h-8 w-36 text-xs"
      value={customTo}
      oninput={(e) => (customTo = (e.target as HTMLInputElement).value)}
    />
    <Button
      size="sm"
      variant={range.kind === 'range' ? 'default' : 'outline'}
      onclick={applyCustomRange}
      disabled={!customFrom || !customTo}
    >
      Apply
    </Button>
  </div>
</div>
