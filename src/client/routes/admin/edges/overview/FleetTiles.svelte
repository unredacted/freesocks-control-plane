<script lang="ts">
  /**
   * The fleet figures as a tile grid. A problem tile with a non-zero count is a
   * button that applies its filter to the origin table (pressed state = active).
   *
   * Props:
   *   tiles: FleetTile[]                       from overview/derive.ts fleetTiles()
   *   activeFilter: OverviewFilter
   *   onFilter: (filter: OverviewFilter) => void
   */
  import { cn } from '@client/lib/utils';
  import type { Tone } from '@client/lib/edgeCodes';
  import type { FleetTile, OverviewFilter } from './derive';

  interface Props {
    tiles: FleetTile[];
    activeFilter: OverviewFilter;
    onFilter: (filter: OverviewFilter) => void;
  }
  let { tiles, activeFilter, onFilter }: Props = $props();

  const VALUE_TONE: Record<Tone, string> = {
    neutral: 'text-foreground',
    muted: 'text-muted-foreground',
    info: 'text-sky-700 dark:text-sky-300',
    success: 'text-emerald-700 dark:text-emerald-300',
    warning: 'text-amber-700 dark:text-amber-300',
    danger: 'text-destructive',
  };
  const BOX = 'bg-card rounded-lg border px-3 py-2.5 text-start';
</script>

{#snippet body(tile: FleetTile)}
  <span class="text-muted-foreground block text-xs">{tile.label}</span>
  <span class={cn('mt-0.5 block text-xl font-semibold tabular-nums', VALUE_TONE[tile.tone])}>
    {tile.value}
  </span>
  <span class="text-muted-foreground mt-0.5 block text-xs">{tile.hint}</span>
{/snippet}

<ul class="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-5" aria-label="Fleet figures">
  {#each tiles as tile (tile.id)}
    <li class="flex">
      {#if tile.filter}
        {@const filter = tile.filter}
        {@const active = activeFilter === filter}
        <button
          type="button"
          class={cn(
            BOX,
            'hover:bg-accent focus-visible:ring-ring/50 w-full outline-none focus-visible:ring-3',
            active && 'ring-primary ring-2',
          )}
          aria-pressed={active}
          aria-label={`${tile.label}: ${tile.value}. ${active ? 'Clear the filter' : 'Filter the origin table'}`}
          onclick={() => onFilter(active ? 'all' : filter)}
        >
          {@render body(tile)}
        </button>
      {:else}
        <div class={cn(BOX, 'w-full')}>{@render body(tile)}</div>
      {/if}
    </li>
  {/each}
</ul>
