<script lang="ts">
  /**
   * The Overview's four small tiles (overviewModel.ts `overviewTiles`): Nodes,
   * Countries, Spend a month, Probe budget. Each opens the tab it summarises.
   *
   * Props:
   *   tiles: Tile[]
   */
  import Link from '@client/components/Link.svelte';
  import { cn } from '@client/lib/utils';
  import type { Tone } from '@client/lib/edgeCodes';
  import type { Tile } from './overviewModel';

  let { tiles }: { tiles: Tile[] } = $props();

  const VALUE_TONE: Record<Tone, string> = {
    neutral: 'text-foreground',
    muted: 'text-muted-foreground',
    info: 'text-sky-700 dark:text-sky-300',
    success: 'text-emerald-700 dark:text-emerald-300',
    warning: 'text-amber-700 dark:text-amber-300',
    danger: 'text-destructive',
  };
</script>

<ul class="grid grid-cols-2 gap-2 lg:grid-cols-4" aria-label="Figures">
  {#each tiles as tile (tile.id)}
    <li class="flex">
      <Link
        href={tile.href}
        class="bg-card hover:bg-accent focus-visible:ring-ring/50 w-full rounded-lg border px-3 py-2.5 text-start outline-none focus-visible:ring-3"
      >
        <span class="text-muted-foreground block text-xs">{tile.label}</span>
        <span class={cn('mt-0.5 block text-xl font-semibold tabular-nums', VALUE_TONE[tile.tone])}>
          {tile.value}
        </span>
        <span class="text-muted-foreground mt-0.5 block text-xs">{tile.hint}</span>
      </Link>
    </li>
  {/each}
</ul>
