<script lang="ts">
  /**
   * An Action needed list (the Overview's, overviewModel.ts `mergeAttention`,
   * and each backend's on Nodes): one line per KIND of problem
   * (overviewModel.ts `groupRows`), most urgent first. A kind with one item is
   * that item's row with its button; a kind with several says how many and who
   * it is about, and opens to the items, each with its own button. Every line
   * is one IssueRow: why it matters, what to do and the raw facts wait behind
   * its disclosure.
   *
   * Edge items are drawn by AttentionList (its words, its confirm dialogs, its
   * server calls through `onAction`); every other row runs a link or one of two
   * backend calls here (Release a hold, Seen it for an edit made on the backend).
   *
   * Props:
   *   rows: OverviewRow[]
   *   onAction?: (item: AttentionItem) => void | Promise<unknown>   edge attention calls
   *                                    (without it an edge row's button navigates)
   *   max?: number                     lines shown before "Show all" (default 6)
   *   title?: string                   the heading (default "Action needed")
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
  import { codeExplain, codeFix, plainWords } from '@client/lib/edgeCodes';
  import { router } from '@client/stores/router.svelte';
  import { acknowledgeForeignEdit, invalidateServers, releaseHold } from '@client/lib/serversApi';
  import AdminListState from '../../AdminListState.svelte';
  import AttentionList from '../../edges/components/AttentionList.svelte';
  import IssueRow from '../../edges/components/IssueRow.svelte';
  import type { AttentionItem } from '../../edges/lib/attention';
  import { codeOf } from '../lib/run';
  import { serverErrorWords } from '../lib/words';
  import {
    groupRows,
    groupSubjects,
    type OverviewGroup,
    type OverviewRow,
    type RowAction,
  } from './overviewModel';

  interface Props {
    rows: OverviewRow[];
    onAction?: (item: AttentionItem) => void | Promise<unknown>;
    max?: number;
    title?: string;
    top?: Snippet;
    edgeError?: unknown;
    onEdgeRetry?: () => void;
  }
  let {
    rows,
    onAction,
    max = 6,
    title = 'Action needed',
    top,
    edgeError = null,
    onEdgeRetry,
  }: Props = $props();

  const uid = $props.id();
  const qc = useQueryClient();
  const groups = $derived(groupRows(rows));
  let showAll = $state(false);
  const shown = $derived(showAll ? groups : groups.slice(0, max));
  let busyKey = $state<string | null>(null);

  const COUNT_WORDS = [
    ['critical', 'critical', 'critical'],
    ['warning', 'warning', 'warnings'],
    ['info', 'note', 'notes'],
  ] as const;
  const counts = $derived(
    COUNT_WORDS.flatMap(([sev, one, many]) => {
      const n = groups.filter((g) => g.severity === sev).length;
      return n > 0 ? [`${n} ${n === 1 ? one : many}`] : [];
    }).join(' · '),
  );

  /** The kind's own words for a group of edge items (each item keeps only its own facts). */
  function edgeKindWords(
    g: OverviewGroup,
  ): { explain: string; fix: string | null; shared: string | null } | null {
    const first = g.rows[0];
    if (!first || first.source !== 'edge') return null;
    // A reason all items share says the fix; mixed reasons leave it to each item.
    const codes = new Set(g.rows.map((r) => (r.source === 'edge' ? r.item.code : null)));
    const shared = codes.size === 1 ? [...codes][0] : null;
    const fix = (shared ? codeFix(shared) : undefined) ?? codeFix(first.item.kind);
    return {
      explain: plainWords(codeExplain(first.item.kind)),
      fix: fix ? plainWords(fix) : null,
      shared: shared ?? null,
    };
  }

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

{#snippet rowButton(
  row: Extract<OverviewRow, { source: 'servers' | 'snis' | 'country' | 'provider' }>,
  nested: boolean,
)}
  {#if row.action}
    {@const action = row.action}
    <Button
      size="sm"
      variant={row.severity === 'critical' && !nested ? 'default' : 'outline'}
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
{/snippet}

{#snippet otherRow(
  row: Extract<OverviewRow, { source: 'servers' | 'snis' | 'country' | 'provider' }>,
  nested: boolean,
)}
  {#snippet details()}<p>{row.detail}</p>{/snippet}
  {#snippet action()}{@render rowButton(row, nested)}{/snippet}
  <IssueRow
    severity={row.severity}
    title={nested ? (row.chip?.label ?? row.text) : row.title}
    subject={nested ? null : (row.chip?.label ?? null)}
    line={nested && !row.chip ? null : row.text}
    {nested}
    details={row.detail ? details : undefined}
    action={row.action ? action : undefined}
  />
{/snippet}

<section aria-labelledby={`${uid}-heading`}>
  <div class="mb-3 flex flex-wrap items-baseline gap-x-3 gap-y-1">
    <h2 id={`${uid}-heading`} class="text-base font-semibold">{title}</h2>
    {#if counts}<span class="text-muted-foreground text-sm">{counts}</span>{/if}
  </div>
  <div class="space-y-3">
    {@render top?.()}
    {#if edgeError}
      <!-- The edge attention read failed: said here, while every other source still lists. -->
      <AdminListState error={edgeError} onRetry={onEdgeRetry} />
    {/if}
    {#if rows.length === 0 && edgeError}
      <!-- Nothing else to list; never "No action needed" while a source is unread. -->
    {:else if rows.length === 0}
      <p class="text-muted-foreground rounded-lg border border-dashed p-6 text-center text-sm">
        No action needed.
      </p>
    {:else}
      <ul class="bg-card divide-y rounded-lg border" aria-label={title}>
        {#each shown as g (g.key)}
          <li>
            {#if g.rows.length === 1}
              {@const row = g.rows[0]!}
              {#if row.source === 'edge'}
                <AttentionList items={[row.item]} {onAction} plain layout="bare" />
              {:else}
                {@render otherRow(row, false)}
              {/if}
            {:else}
              {@const kind = edgeKindWords(g)}
              {#snippet groupDetails()}
                {#if kind}
                  <p>{kind.explain}</p>
                  {#if kind.fix}
                    <p><span class="text-foreground font-medium">What to do:</span> {kind.fix}</p>
                  {/if}
                  <AttentionList
                    items={g.rows.flatMap((r) => (r.source === 'edge' ? [r.item] : []))}
                    {onAction}
                    plain
                    layout="nested"
                    sharedCode={kind.shared}
                    class="bg-background mt-2"
                  />
                {:else}
                  <ul class="bg-background mt-1 divide-y rounded-md border">
                    {#each g.rows as row (row.key)}
                      {#if row.source !== 'edge'}
                        <li>{@render otherRow(row, true)}</li>
                      {/if}
                    {/each}
                  </ul>
                {/if}
              {/snippet}
              <IssueRow
                severity={g.severity}
                title={g.title}
                count={g.rows.length}
                subject={groupSubjects(g)}
                details={groupDetails}
              />
            {/if}
          </li>
        {/each}
      </ul>
      {#if groups.length > max && !showAll}
        <Button variant="ghost" size="sm" onclick={() => (showAll = true)}>
          Show all {groups.length}
        </Button>
      {/if}
    {/if}
  </div>
</section>
