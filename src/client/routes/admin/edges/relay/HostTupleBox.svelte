<script lang="ts">
  /**
   * One Host tuple of the quarantine resolver (address:port, server name, Host
   * header), optionally highlighted as the one the panel serves.
   *
   * Props: title; tuple (null = none); emptyText; highlight?; tone?; edgeId?; uuid?; onOpenEdge?
   */
  import type { HostTuple } from '@shared/contracts/edges';
  import { cn } from '@client/lib/utils';
  import { Badge } from '@client/components/ui/badge';
  import { shortId } from '../lib/time';
  import { tupleLine } from './relayLogic';

  interface Props {
    title: string;
    tuple: HostTuple | null;
    emptyText: string;
    highlight?: boolean;
    tone?: 'match' | 'mismatch' | 'plain';
    edgeId?: string | null;
    uuid?: string | null;
    onOpenEdge?: (edgeId: string) => void;
  }
  let {
    title,
    tuple,
    emptyText,
    highlight = false,
    tone = 'plain',
    edgeId = null,
    uuid = null,
    onOpenEdge,
  }: Props = $props();
</script>

<div
  class={cn(
    'rounded-md border p-3 text-sm',
    highlight && 'border-emerald-500/60 bg-emerald-500/10',
    tone === 'match' && 'border-emerald-500/60',
    tone === 'mismatch' && 'border-destructive/50 bg-destructive/5',
  )}
>
  <div class="mb-1.5 flex flex-wrap items-center gap-1.5">
    <h4 class="text-xs font-semibold tracking-wide text-muted-foreground uppercase">{title}</h4>
    {#if highlight}
      <Badge variant="success">The panel serves this</Badge>
    {/if}
  </div>
  {#if tuple}
    <dl class="space-y-0.5">
      <div class="font-mono text-xs break-all">{tupleLine(tuple)}</div>
      <div class="text-xs text-muted-foreground">
        Server name: <span class="font-mono">{tuple.sni ?? 'none'}</span>
      </div>
      <div class="text-xs text-muted-foreground">
        Host header: <span class="font-mono">{tuple.host ?? 'none'}</span>
      </div>
      {#if uuid}
        <div class="text-xs text-muted-foreground">
          Panel Host: <span class="font-mono">{uuid}</span>
        </div>
      {/if}
      {#if edgeId}
        <button
          type="button"
          class="text-xs text-primary hover:underline"
          onclick={() => onOpenEdge?.(edgeId)}
        >
          Open edge {shortId(edgeId)}
        </button>
      {/if}
    </dl>
  {:else}
    <p class="text-xs text-muted-foreground">{emptyText}</p>
  {/if}
</div>
