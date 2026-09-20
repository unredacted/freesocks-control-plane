<script lang="ts">
  /**
   * One protected node on the home: name, country, one plain sentence, a dot.
   * The row is a link to the node page; a live run shows "Setting up, step N of
   * 4" and opens the progress sheet instead.
   *
   * Props:
   *   row: RelayRow                       one EdgeSummary origin row
   *   status: NodeStatus                  from nodeStatus()
   *   runId?: string | null               the live run (the row opens its progress)
   *   onOpenRun?: (runId: string) => void
   */
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import Link from '@client/components/Link.svelte';
  import { countryName } from '@client/lib/countries';
  import { edgesPaths } from '../lib/routes';
  import StatusDot from './StatusDot.svelte';
  import type { NodeStatus, RelayRow } from './nodeStatus';

  interface Props {
    row: RelayRow;
    status: NodeStatus;
    runId?: string | null;
    onOpenRun?: (runId: string) => void;
  }
  let { row, status, runId = null, onOpenRun }: Props = $props();

  const relay = $derived(row.relay);
  const name = $derived(
    relay.label ?? (relay.origin.kind === 'panel-node' ? relay.origin.nodeName : relay.slug),
  );
  const country = $derived(relay.locationCode ? countryName(relay.locationCode, 'en') : null);
  const ROW =
    'bg-card hover:bg-accent/40 focus-visible:ring-ring/50 flex min-h-14 w-full items-center gap-3 rounded-lg border px-3 py-2.5 text-start outline-none focus-visible:ring-3';
</script>

{#snippet body()}
  <StatusDot dot={status.dot} />
  <span class="min-w-0 flex-1">
    <span class="flex flex-wrap items-baseline gap-x-2">
      <span class="font-medium">{name}</span>
      {#if country}<span class="text-muted-foreground text-xs">{country}</span>{/if}
    </span>
    <span class="text-muted-foreground block text-sm">{status.sentence}</span>
  </span>
  <ChevronRight class="text-muted-foreground size-4 shrink-0 rtl:rotate-180" aria-hidden="true" />
{/snippet}

{#if runId && onOpenRun}
  <button type="button" class={ROW} onclick={() => onOpenRun(runId)}>
    {@render body()}
  </button>
{:else}
  <Link href={edgesPaths.node(relay.slug)} class={ROW}>
    {@render body()}
  </Link>
{/if}
