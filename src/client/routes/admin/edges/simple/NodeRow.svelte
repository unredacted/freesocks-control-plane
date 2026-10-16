<script lang="ts">
  /**
   * One protected node on the home: name, country, one plain sentence, a dot.
   * The sentence and the dot are the server's status of the origin (worded by
   * lib/statusWords.ts). The row links to the node's page; a live run shows
   * "Setting up, step N of 4" and opens the progress sheet instead.
   *
   * Props:
   *   row: OriginRow                       one EdgeSummary origin row
   *   status: OriginStatus | null          the server's status (null while it loads)
   *   href: string                         the node's page
   *   onOpenRun?: (runId: string) => void
   */
  import type { z } from 'zod';
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import Link from '@client/components/Link.svelte';
  import { countryName } from '@client/lib/countries';
  import type { EdgeSummary, OriginStatus } from '@shared/contracts/edges';
  import { originSentence } from '../lib/statusWords';
  import StatusDot from './StatusDot.svelte';

  type OriginRow = z.infer<typeof EdgeSummary>['relays'][number];
  interface Props {
    row: OriginRow;
    status: OriginStatus | null;
    href: string;
    onOpenRun?: (runId: string) => void;
  }
  let { row, status, href, onOpenRun }: Props = $props();

  const relay = $derived(row.relay);
  const runId = $derived(status?.runId ?? null);
  const name = $derived(
    relay.label ?? (relay.origin.kind === 'panel-node' ? relay.origin.nodeName : relay.slug),
  );
  const country = $derived(relay.locationCode ? countryName(relay.locationCode, 'en') : null);
  const ROW =
    'bg-card hover:bg-accent/40 focus-visible:ring-ring/50 flex min-h-14 w-full items-center gap-3 rounded-lg border px-3 py-2.5 text-start outline-none focus-visible:ring-3';
</script>

{#snippet body()}
  <StatusDot dot={status?.dot ?? 'grey'} />
  <span class="min-w-0 flex-1">
    <span class="flex flex-wrap items-baseline gap-x-2">
      <span class="font-medium">{name}</span>
      {#if country}<span class="text-muted-foreground text-xs">{country}</span>{/if}
    </span>
    {#if status}
      <span class="text-muted-foreground block text-sm">{originSentence(status)}</span>
    {:else}
      <span class="bg-muted mt-1 block h-4 w-48 animate-pulse rounded-md" aria-hidden="true"></span>
    {/if}
  </span>
  <ChevronRight class="text-muted-foreground size-4 shrink-0 rtl:rotate-180" aria-hidden="true" />
{/snippet}

{#if runId && onOpenRun}
  <button type="button" class={ROW} onclick={() => onOpenRun(runId)}>
    {@render body()}
  </button>
{:else}
  <Link {href} class={ROW}>
    {@render body()}
  </Link>
{/if}
