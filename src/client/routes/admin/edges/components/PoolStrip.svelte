<script lang="ts">
  /**
   * An origin's pool as a strip of small cells: published slots by pool index,
   * wanted-but-empty slots, standbys, draining edges. Slot computation is pure
   * (lib/pool.ts). With `onSelect`, cells that carry an edge id are buttons.
   *
   * Props:
   *   publishedEdgeIds: Array<string | null>   OriginAdmin.publishedEdgeIds (index = pool index)
   *   desired: number                          OriginAdmin.desiredPublished
   *   standbys?: string[] | number             OriginAdmin.standbyEdgeIds, or RelayPoolSummary.standbys
   *   draining?: number                        RelayPoolSummary.draining
   *   entries?: PoolEntry[]                    RelayPoolSummary.pool: tints published cells by health
   *   onSelect?: (edgeId: string) => void      e.g. open the edge drawer
   *   showCaption?: boolean                    "2 of 3 published, 1 standby" next to the strip (default false)
   *   class?: string
   */
  import { cn } from '@client/lib/utils';
  import { healthLabel } from '@client/lib/edgeCodes';
  import { poolSlots, poolSummary, type PoolSlot } from '../lib/pool';
  import type { PoolEntry } from '../lib/types';

  interface Props {
    publishedEdgeIds: Array<string | null>;
    desired: number;
    standbys?: string[] | number;
    draining?: number;
    entries?: PoolEntry[];
    onSelect?: (edgeId: string) => void;
    showCaption?: boolean;
    class?: string;
  }
  let {
    publishedEdgeIds,
    desired,
    standbys = 0,
    draining = 0,
    entries = [],
    onSelect,
    showCaption = false,
    class: className,
  }: Props = $props();

  const input = $derived({ publishedEdgeIds, desired, standbys, draining });
  const slots = $derived(poolSlots(input));
  const summary = $derived(poolSummary(input));
  const byEdge = $derived(new Map(entries.map((e) => [e.edgeId, e])));

  function cellClass(slot: PoolSlot): string {
    switch (slot.kind) {
      case 'published': {
        const e = slot.edgeId ? byEdge.get(slot.edgeId) : undefined;
        if (e && (e.health === 'offline' || e.unreachableIn.length > 0))
          return 'bg-destructive border-destructive';
        if (e && (e.health === 'degraded' || e.mixedIn.length > 0))
          return 'bg-amber-500 border-amber-500';
        return 'bg-emerald-500 border-emerald-500';
      }
      case 'missing':
        return 'border-dashed border-amber-500/70 bg-amber-500/10';
      case 'vacant':
        return 'border-dashed border-border bg-transparent';
      case 'standby':
        return 'bg-sky-500/60 border-sky-500/60';
      case 'draining':
        return 'bg-muted-foreground/40 border-muted-foreground/40';
    }
  }

  function cellTitle(slot: PoolSlot): string {
    switch (slot.kind) {
      case 'published': {
        const e = slot.edgeId ? byEdge.get(slot.edgeId) : undefined;
        const bits = [`Slot ${(slot.poolIndex ?? 0) + 1}: published`];
        if (e) bits.push(healthLabel(e.health).toLowerCase());
        if (e && e.unreachableIn.length > 0)
          bits.push(`unreachable in ${e.unreachableIn.join(', ')}`);
        if (slot.surplus) bits.push('beyond the desired size');
        return bits.join(', ');
      }
      case 'missing':
        return `Slot ${(slot.poolIndex ?? 0) + 1}: wanted, nothing published`;
      case 'vacant':
        return `Slot ${(slot.poolIndex ?? 0) + 1}: empty`;
      case 'standby':
        return 'Standby edge, ready to publish';
      case 'draining':
        return 'Draining edge, leaving the pool';
    }
  }

  const CELL = 'inline-block h-3 w-4 rounded-[3px] border';
</script>

<div class={cn('inline-flex items-center gap-2', className)}>
  <div class="inline-flex items-center gap-0.5" role="group" aria-label={`Pool: ${summary}`}>
    {#each slots as slot, i (i)}
      {#if slot.kind !== 'published' && i > 0 && slots[i - 1]?.poolIndex !== null && slot.poolIndex === null}
        <span class="bg-border mx-0.5 h-3 w-px" aria-hidden="true"></span>
      {/if}
      {#if onSelect && slot.edgeId}
        {@const edgeId = slot.edgeId}
        <button
          type="button"
          class={cn(
            CELL,
            cellClass(slot),
            'focus-visible:ring-ring/60 cursor-pointer outline-none hover:opacity-80 focus-visible:ring-3',
          )}
          title={cellTitle(slot)}
          aria-label={`${cellTitle(slot)}. Open edge.`}
          onclick={() => onSelect(edgeId)}
        ></button>
      {:else}
        <span class={cn(CELL, cellClass(slot))} title={cellTitle(slot)} aria-hidden="true"></span>
      {/if}
    {/each}
    {#if slots.length === 0}
      <span class="text-muted-foreground text-xs">No pool</span>
    {/if}
  </div>
  {#if showCaption}
    <span class="text-muted-foreground text-xs">{summary}</span>
  {/if}
</div>
