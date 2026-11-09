<script lang="ts">
  /**
   * The Overview's ONE Action needed list (overviewModel.ts `mergeAttention`):
   * most urgent first, one button per row. An edge attention row is drawn by
   * AttentionList itself (its words, its confirm dialogs, its server calls
   * through `onAction`); every other row says what it is about (a chip), one
   * sentence, and its button: a link, or one of two backend calls run here
   * (Release a hold, Seen it for an edit made on the backend).
   *
   * Props:
   *   rows: OverviewRow[]
   *   onAction: (item: AttentionItem) => void | Promise<unknown>   edge attention calls
   *   max?: number                     rows shown before "Show all" (default 5)
   *   top?: Snippet                    drawn above the rows (the endpoint test card)
   *   edgeError?: unknown              the edge attention read failed: shown inline, the
   *                                    other sources' rows still list
   *   onEdgeRetry?: () => void         reads edge attention again
   */
  import type { Snippet } from 'svelte';
  import { useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import ChevronRight from '@lucide/svelte/icons/chevron-right';
  import { Button } from '@client/components/ui/button';
  import { cn } from '@client/lib/utils';
  import { router } from '@client/stores/router.svelte';
  import { acknowledgeForeignEdit, invalidateServers, releaseHold } from '@client/lib/serversApi';
  import AdminListState from '../../AdminListState.svelte';
  import AttentionList from '../../edges/components/AttentionList.svelte';
  import StatusBadge from '../../edges/components/StatusBadge.svelte';
  import type { AttentionItem } from '../../edges/lib/attention';
  import { codeOf } from '../lib/run';
  import { serverErrorWords } from '../lib/words';
  import type { OverviewRow, RowAction } from './overviewModel';

  interface Props {
    rows: OverviewRow[];
    onAction: (item: AttentionItem) => void | Promise<unknown>;
    max?: number;
    top?: Snippet;
    edgeError?: unknown;
    onEdgeRetry?: () => void;
  }
  let { rows, onAction, max = 5, top, edgeError = null, onEdgeRetry }: Props = $props();

  const qc = useQueryClient();
  let showAll = $state(false);
  const shown = $derived(showAll ? rows : rows.slice(0, max));
  let busyKey = $state<string | null>(null);

  const BORDER = {
    critical: 'border-s-destructive',
    warning: 'border-s-amber-500',
    info: 'border-s-sky-500',
  } as const;

  async function act(key: string, action: RowAction): Promise<void> {
    if (action.kind === 'link') {
      router.navigate(action.href);
      return;
    }
    busyKey = key;
    try {
      if (action.kind === 'release') {
        await releaseHold(action.slug, action.holdId);
        toast.success('Hold released.');
      } else {
        await acknowledgeForeignEdit(action.slug, action.profileUuid);
      }
    } catch (e) {
      toast.error(serverErrorWords(codeOf(e)));
    } finally {
      busyKey = null;
      invalidateServers(qc);
    }
  }
</script>

<section aria-labelledby="action-needed">
  <h2 id="action-needed" class="mb-3 text-base font-semibold">Action needed</h2>
  <div class="space-y-3">
    {@render top?.()}
    {#if edgeError}
      <!-- The edge attention read failed: said here, while every other source still lists. -->
      <AdminListState error={edgeError} onRetry={onEdgeRetry} />
    {/if}
    {#if rows.length === 0 && edgeError}
      <!-- Nothing else to list; never "Nothing needs you" while a source is unread. -->
    {:else if rows.length === 0}
      <p class="text-muted-foreground rounded-lg border border-dashed p-6 text-center text-sm">
        Nothing needs you.
      </p>
    {:else}
      <ul class="space-y-2" aria-label="Action needed">
        {#each shown as row (row.key)}
          <li>
            {#if row.source === 'edge'}
              <AttentionList items={[row.item]} {onAction} plain />
            {:else}
              <div
                class={cn(
                  'bg-card flex flex-wrap items-start gap-x-4 gap-y-2 rounded-lg border border-s-4 px-3 py-2.5',
                  BORDER[row.severity],
                )}
              >
                <div class="min-w-0 flex-1 basis-64">
                  <div class="flex flex-wrap items-center gap-2">
                    <StatusBadge kind="severity" value={row.severity} />
                    {#if row.chip}
                      <span class="text-sm font-medium">{row.chip.label}</span>
                    {/if}
                  </div>
                  <p class="text-muted-foreground mt-1 text-sm">{row.text}</p>
                </div>
                {#if row.action}
                  {@const action = row.action}
                  <Button
                    size="sm"
                    variant={row.severity === 'critical' ? 'default' : 'outline'}
                    disabled={busyKey === row.key}
                    aria-label={row.chip ? `${action.label}: ${row.chip.label}` : action.label}
                    onclick={() => void act(row.key, action)}
                  >
                    {busyKey === row.key ? 'Working…' : action.label}
                    {#if action.kind === 'link'}
                      <ChevronRight class="rtl:rotate-180" aria-hidden="true" />
                    {/if}
                  </Button>
                {/if}
              </div>
            {/if}
          </li>
        {/each}
      </ul>
      {#if rows.length > max && !showAll}
        <Button variant="ghost" size="sm" onclick={() => (showAll = true)}>
          Show all {rows.length}
        </Button>
      {/if}
    {/if}
  </div>
</section>
