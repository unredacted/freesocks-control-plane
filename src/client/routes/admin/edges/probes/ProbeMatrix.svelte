<script lang="ts">
  /**
   * Reachability matrix: the last verdict per probe target and country.
   * Self-contained (queries the matrix, requests probes, expands run history);
   * renders no Card of its own so a page can place it anywhere.
   *
   * Props:
   *   filter?: (targetKey: string) => boolean   keep only these targets (`edge:<id>` / `origin:<id>` / `custom:<id>`)
   *   compact?: boolean                         no selection column, no group headings, no "updated" column
   *   openTarget?: string | null                the target whose run history is expanded (controlled; e.g. from `?target=`)
   *   onOpenTarget?: (key: string | null) => void
   *                                             when omitted the expansion is local state
   *   emptyText?: string                        shown when nothing matches
   */
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import { Badge } from '@client/components/ui/badge';
  import { Button } from '@client/components/ui/button';
  import { Checkbox } from '@client/components/ui/checkbox';
  import { Skeleton } from '@client/components/ui/skeleton';
  import * as Table from '@client/components/ui/table';
  import * as Tooltip from '@client/components/ui/tooltip';
  import AdminListState from '../../AdminListState.svelte';
  import { invalidateProbes, probeMatrixQuery, requestProbes } from '../../../../lib/edgesApi';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import { relativeTime } from '../lib/time';
  import ProbeRunsTable from './ProbeRunsTable.svelte';
  import {
    INTERNAL_COUNTRY,
    KIND_SINGULAR,
    groupTargets,
    matrixCell,
    probeRequestSummary,
    skipNotes,
    targetDetail,
  } from './matrix';

  interface Props {
    filter?: (targetKey: string) => boolean;
    compact?: boolean;
    openTarget?: string | null;
    onOpenTarget?: (key: string | null) => void;
    emptyText?: string;
  }
  let {
    filter,
    compact = false,
    openTarget,
    onOpenTarget,
    emptyText = 'Nothing to probe yet. Publish an edge, opt an origin node in, or add a custom target.',
  }: Props = $props();

  const qc = useQueryClient();
  const matrix = probeMatrixQuery();
  const groups = $derived(groupTargets(matrix.data?.targets ?? [], filter));
  const countries = $derived(matrix.data?.countries ?? []);
  const columnCount = $derived(countries.length + (compact ? 3 : 5));

  let localOpen = $state<string | null>(null);
  const opened = $derived(onOpenTarget ? (openTarget ?? null) : localOpen);
  function toggleRuns(key: string) {
    const next = opened === key ? null : key;
    if (onOpenTarget) onOpenTarget(next);
    else localOpen = next;
  }

  let selected = $state<Set<string>>(new Set());
  function toggle(key: string, on: boolean) {
    const next = new Set(selected);
    if (on) next.add(key);
    else next.delete(key);
    selected = next;
  }
  /** Why a target was left out of the last request, in words, by target key. */
  let notes = $state<Record<string, string>>({});

  const probeNow = createMutation(() => ({
    mutationFn: (keys: string[]) => requestProbes(keys),
    onSuccess: (res) => {
      selected = new Set();
      notes = { ...notes, ...skipNotes(res.skipped) };
      invalidateProbes(qc);
      if (res.runIds.length === 0 && res.skipped.length > 0) {
        toast.warning(probeRequestSummary(res));
      } else {
        toast.success(probeRequestSummary(res));
      }
    },
    onError: (err: unknown) =>
      toast.error('Probe request refused', { description: edgeErrorMessage(err) }),
  }));
</script>

{#if matrix.isPending}
  <Skeleton class="h-24 w-full" />
{:else if matrix.isError}
  <AdminListState error={matrix.error} onRetry={() => void matrix.refetch()} />
{:else if groups.length === 0}
  <AdminListState {emptyText} />
{:else}
  {#if !compact}
    <div class="mb-2 flex items-center justify-end">
      <Button
        size="sm"
        disabled={selected.size === 0 || probeNow.isPending}
        onclick={() => probeNow.mutate([...selected])}
      >
        {selected.size === 0 ? 'Probe selected now' : `Probe ${selected.size} selected now`}
      </Button>
    </div>
  {/if}
  <Table.Root class="text-xs">
    <Table.Header>
      <Table.Row>
        {#if !compact}<Table.Head class="w-8"><span class="sr-only">Select</span></Table.Head>{/if}
        <Table.Head>Target</Table.Head>
        {#each countries as c (c)}<Table.Head>{c}</Table.Head>{/each}
        <Table.Head>
          <Tooltip.Root>
            <Tooltip.Trigger class="cursor-help underline decoration-dotted">FCP</Tooltip.Trigger>
            <Tooltip.Content>
              The internal connect check from FCP itself. Failing here too means an outage, not a
              block.
            </Tooltip.Content>
          </Tooltip.Root>
        </Table.Head>
        {#if !compact}<Table.Head>Updated</Table.Head>{/if}
        <Table.Head><span class="sr-only">Actions</span></Table.Head>
      </Table.Row>
    </Table.Header>
    <Table.Body>
      {#each groups as g (g.kind)}
        {#if !compact}
          <Table.Row class="bg-muted/40 hover:bg-muted/40">
            <Table.Cell
              colspan={columnCount}
              class="py-1 text-[11px] font-semibold tracking-wider text-muted-foreground uppercase"
            >
              {g.label}
              {#if g.kind !== 'edge'}
                <span class="font-normal tracking-normal normal-case">
                  (operator evidence, the block detector does not read these)
                </span>
              {/if}
            </Table.Cell>
          </Table.Row>
        {/if}
        {#each g.targets as t (t.key)}
          <Table.Row class={t.enabled ? '' : 'opacity-75'}>
            {#if !compact}
              <Table.Cell>
                <Checkbox
                  aria-label={`Select ${t.label}`}
                  checked={selected.has(t.key)}
                  onCheckedChange={(v) => toggle(t.key, v === true)}
                />
              </Table.Cell>
            {/if}
            <Table.Cell>
              <div class="font-medium">{t.label}</div>
              <div class="text-muted-foreground">
                {#if compact}{KIND_SINGULAR[t.kind]}{:else}{targetDetail(t)}{/if}{t.enabled
                  ? ''
                  : ', on demand only'}
              </div>
              {#if notes[t.key]}
                <div class="text-amber-700 dark:text-amber-300">Last request: {notes[t.key]}</div>
              {/if}
            </Table.Cell>
            {#each [...countries, INTERNAL_COUNTRY] as c (c)}
              {@const x = matrixCell(t, c)}
              <Table.Cell>
                {#if x.probed}
                  <Tooltip.Root>
                    <Tooltip.Trigger>
                      <Badge variant={x.tone}>{x.label}</Badge>
                    </Tooltip.Trigger>
                    <Tooltip.Content>
                      {x.vantages}{x.lastAt ? `, ${relativeTime(x.lastAt)}` : ''}
                    </Tooltip.Content>
                  </Tooltip.Root>
                  {#each x.extras as e (e)}
                    <div class="mt-0.5 text-[11px] text-muted-foreground">{e}</div>
                  {/each}
                {:else}
                  <span class="text-muted-foreground">{x.label}</span>
                {/if}
              </Table.Cell>
            {/each}
            {#if !compact}
              <Table.Cell class="whitespace-nowrap text-muted-foreground">
                {t.reachability.updatedAt ? relativeTime(t.reachability.updatedAt) : 'Never'}
              </Table.Cell>
            {/if}
            <Table.Cell class="text-right whitespace-nowrap">
              <Button
                size="sm"
                variant="ghost"
                class="h-7 px-2 text-xs"
                disabled={probeNow.isPending}
                onclick={() => probeNow.mutate([t.key])}>Probe now</Button
              >
              <Button
                size="sm"
                variant="ghost"
                class="h-7 px-2 text-xs"
                aria-expanded={opened === t.key}
                onclick={() => toggleRuns(t.key)}>{opened === t.key ? 'Hide runs' : 'Runs'}</Button
              >
            </Table.Cell>
          </Table.Row>
          {#if opened === t.key}
            <Table.Row class="bg-muted/30 hover:bg-muted/30">
              <Table.Cell colspan={columnCount} class="p-3">
                <ProbeRunsTable targetKey={t.key} />
              </Table.Cell>
            </Table.Row>
          {/if}
        {/each}
      {/each}
    </Table.Body>
  </Table.Root>
{/if}
