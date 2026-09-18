<script lang="ts">
  /**
   * What members of one relay would receive, per client family: the body the
   * panel serves next to the body FCP would send, and every listener whose entry
   * did not resolve, in words. Read only (the preview writes nothing).
   *
   * Props:
   *   relayId: string
   *   family?: RenderClientFamily        the tab to open first (default 'singbox')
   *   class?: string
   */
  import { untrack } from 'svelte';
  import { createQuery } from '@tanstack/svelte-query';
  import CircleCheck from '@lucide/svelte/icons/circle-check';
  import * as Tabs from '@client/components/ui/tabs';
  import { Button } from '@client/components/ui/button';
  import { Skeleton } from '@client/components/ui/skeleton';
  import { RENDER_CLIENT_FAMILY_IDS, type RenderClientFamily } from '@shared/contracts/edges';
  import { edgeKeys, previewRender } from '@client/lib/edgesApi';
  import { cn } from '@client/lib/utils';
  import AdminListState from '../../AdminListState.svelte';
  import CodeNote from '../components/CodeNote.svelte';
  import CopyButton from '../components/CopyButton.svelte';
  import { FAMILY_LABELS, FORMAT_LABELS } from './renderLabels';

  interface Props {
    relayId: string;
    family?: RenderClientFamily;
    class?: string;
  }
  let { relayId, family: initialFamily = 'singbox', class: className }: Props = $props();

  let family = $state<RenderClientFamily>(untrack(() => initialFamily));

  const preview = createQuery(() => ({
    queryKey: [...edgeKeys.all, 'render-preview', relayId, family] as const,
    queryFn: () => previewRender({ relayId, family }),
    enabled: relayId !== '',
    staleTime: 15_000,
    retry: false,
  }));

  const data = $derived(preview.data);
  const mismatches = $derived((data?.listeners ?? []).filter((l) => !l.matched));
  const matched = $derived((data?.listeners ?? []).filter((l) => l.matched));
  const unavailable = $derived(data?.delivery?.kind === 'unavailable' ? data.delivery : null);
</script>

<div class={cn('space-y-3', className)}>
  <Tabs.Root value={family} onValueChange={(v: string) => (family = v as RenderClientFamily)}>
    <Tabs.List class="h-auto flex-wrap justify-start" aria-label="Client family">
      {#each RENDER_CLIENT_FAMILY_IDS as f (f)}
        <Tabs.Trigger value={f}>{FAMILY_LABELS[f]}</Tabs.Trigger>
      {/each}
    </Tabs.List>
  </Tabs.Root>

  {#if preview.isError}
    <AdminListState error={preview.error} onRetry={() => void preview.refetch()} />
  {:else if preview.isPending}
    <div class="space-y-2" role="status">
      <span class="sr-only">Rendering the preview</span>
      <Skeleton class="h-8 w-1/2" />
      <Skeleton class="h-40 w-full" />
    </div>
  {:else if data}
    <div class="flex flex-wrap items-center justify-between gap-2">
      <p class="text-sm">
        {#if data.applied && data.emitted > 0}
          <CircleCheck
            class="me-1 inline size-4 text-emerald-600 dark:text-emerald-400"
            aria-hidden="true"
          />
          <span class="font-medium">Rewritten.</span>
          {data.emitted}
          {data.emitted === 1 ? 'entry points' : 'entries point'} at an edge ({FORMAT_LABELS[
            data.format
          ]}).
        {:else}
          <span class="font-medium">Not rewritten for this family.</span>
          Members on it would not get a usable body.
        {/if}
      </p>
      <Button
        size="sm"
        variant="outline"
        disabled={preview.isFetching}
        onclick={() => void preview.refetch()}
      >
        {preview.isFetching ? 'Rendering' : 'Render again'}
      </Button>
    </div>

    {#if !data.applied && data.reason}
      <CodeNote issue={{ code: data.reason }} tone="blocker" />
    {/if}
    {#if unavailable}
      <CodeNote
        issue={{
          code: unavailable.reason,
          detail: 'Members on this relay receive a temporary failure instead of a subscription.',
        }}
        tone="blocker"
      />
    {/if}

    {#if mismatches.length > 0}
      <div class="space-y-1.5">
        <p class="text-sm font-medium">
          {mismatches.length}
          {mismatches.length === 1 ? 'listener has' : 'listeners have'} no rewritten entry
        </p>
        {#each mismatches as l (l.listenerKey)}
          <CodeNote
            issue={{ code: l.reason ?? 'no_match', subject: `listener ${l.listenerKey}` }}
            tone="warning"
          />
        {/each}
      </div>
    {/if}
    {#if matched.length > 0}
      <p class="text-muted-foreground text-xs">
        Resolved for {matched.length === 1 ? 'listener' : 'listeners'}
        {matched.map((l) => l.listenerKey).join(', ')}.
      </p>
    {/if}

    <div class="grid gap-3 lg:grid-cols-2">
      {#each [{ title: 'What the panel serves', hint: 'The input: it still dials the origin.', text: data.input }, { title: 'What members receive', hint: 'The output: origin entries replaced by edge entries.', text: data.body }] as pane (pane.title)}
        <section class="min-w-0 space-y-1">
          <div class="flex items-center justify-between gap-2">
            <div>
              <h4 class="text-sm font-medium">{pane.title}</h4>
              <p class="text-muted-foreground text-xs">{pane.hint}</p>
            </div>
            {#if pane.text}<CopyButton value={pane.text} label={`Copy: ${pane.title}`} />{/if}
          </div>
          {#if pane.text}
            <!-- svelte-ignore a11y_no_noninteractive_tabindex (a scrollable region must be keyboard reachable) -->
            <pre
              class="bg-muted max-h-80 overflow-auto rounded-md p-2 text-xs leading-relaxed break-all whitespace-pre-wrap"
              tabindex="0">{pane.text}</pre>
          {:else}
            <p
              class="text-muted-foreground rounded-md border border-dashed p-4 text-center text-sm"
            >
              Empty.
            </p>
          {/if}
        </section>
      {/each}
    </div>
  {/if}
</div>
