<script lang="ts" module>
  /** Non-config parts of a section's patch (write-only secrets), with their diff lines. */
  export interface ExtraChanges {
    patch: Record<string, unknown>;
    lines: string[];
  }
</script>

<script lang="ts">
  /**
   * One settings section: a card (optionally collapsible) holding its fields, the
   * list of pending changes (old -> new) and ONE Save that sends only the changed
   * keys of this section as a flat patch. After the save the fresh config is
   * fetched and any value the server stored differently is reported.
   *
   * Props:
   *   id: string                               anchor id (`settings-<id>`)
   *   title, description: string
   *   form: ConfigForm
   *   paths: string[]                          the flat paths this section owns
   *   collapsible?: boolean                    default false
   *   open?: boolean                           for a collapsible card
   *   onToggle?: (open: boolean) => void
   *   note?: string                            shown above Save when there are changes
   *   extra?: () => ExtraChanges | null        non-config parts of the patch (write-only secrets)
   *   onSaved?: () => void                     clear the extra inputs
   *   children: Snippet
   */
  import type { Snippet } from 'svelte';
  import { createMutation, useQueryClient } from '@tanstack/svelte-query';
  import { toast } from 'svelte-sonner';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import { Button } from '@client/components/ui/button';
  import { Badge } from '@client/components/ui/badge';
  import InlineError from '@client/components/InlineError.svelte';
  import { cn } from '@client/lib/utils';
  import {
    edgeKeys,
    fetchEdgeConfig,
    invalidateConfig,
    patchEdgeConfig,
  } from '@client/lib/edgesApi';
  import { edgeErrorMessage } from '../lib/edgeErrors';
  import {
    adjustedValues,
    flattenConfig,
    formatConfigValue,
    type AdjustedValue,
    type FlatConfig,
  } from './configDiff';
  import type { ConfigForm } from './form.svelte';

  interface Props {
    id: string;
    title: string;
    description: string;
    form: ConfigForm;
    paths: string[];
    collapsible?: boolean;
    open?: boolean;
    onToggle?: (open: boolean) => void;
    note?: string;
    extra?: () => ExtraChanges | null;
    onSaved?: () => void;
    children: Snippet;
  }
  let {
    id,
    title,
    description,
    form,
    paths,
    collapsible = false,
    open = true,
    onToggle,
    note,
    extra,
    onSaved,
    children,
  }: Props = $props();

  const qc = useQueryClient();
  const changes = $derived(form.changes(paths));
  const extraChanges = $derived(extra?.() ?? null);
  const count = $derived(changes.length + (extraChanges?.lines.length ?? 0));
  const invalid = $derived(form.hasInvalid(paths));
  // A section with unsaved edits never hides them.
  const shown = $derived(!collapsible || open || count > 0 || invalid);

  let adjusted = $state<AdjustedValue[]>([]);
  // Bumped on save / discard: remounts the fields so a half-typed number is dropped too.
  let epoch = $state(0);

  const save = createMutation(() => ({
    mutationFn: async () => {
      const sent: FlatConfig = form.patch(paths);
      const body = { ...sent, ...(extraChanges?.patch ?? {}) };
      const res = await patchEdgeConfig(body);
      const fresh = await qc.fetchQuery({
        queryKey: edgeKeys.config,
        queryFn: fetchEdgeConfig,
        staleTime: 0,
      });
      return { res, sent, fresh };
    },
    onSuccess: ({ res, sent, fresh }) => {
      adjusted = adjustedValues(sent, flattenConfig(fresh.config));
      form.discard(paths);
      epoch++;
      onSaved?.();
      invalidateConfig(qc);
      const n = res.changedKeys.length;
      toast.success(
        n === 0
          ? `${title}: nothing needed saving.`
          : `${title}: saved ${n} ${n === 1 ? 'setting' : 'settings'}.`,
      );
    },
  }));

  function discard() {
    form.discard(paths);
    epoch++;
    onSaved?.();
    save.reset();
  }
</script>

<section
  id={`settings-${id}`}
  class="bg-card ring-foreground/15 scroll-mt-20 rounded-xl ring-1"
  aria-labelledby={`settings-${id}-title`}
>
  <header class="flex flex-wrap items-start gap-3 px-4 py-3">
    <div class="min-w-0 flex-1">
      <h2 id={`settings-${id}-title`} class="flex flex-wrap items-center gap-2 font-medium">
        {title}
        {#if count > 0}
          <Badge variant="warning">{count} unsaved</Badge>
        {/if}
      </h2>
      <p class="text-muted-foreground mt-0.5 text-sm">{description}</p>
    </div>
    {#if collapsible}
      <Button
        variant="ghost"
        size="sm"
        aria-expanded={shown}
        aria-controls={`settings-${id}-body`}
        disabled={count > 0 || invalid}
        onclick={() => onToggle?.(!open)}
      >
        {shown ? 'Hide' : 'Show'}
        <ChevronDown class={cn('transition-transform', shown && 'rotate-180')} aria-hidden="true" />
      </Button>
    {/if}
  </header>

  <div id={`settings-${id}-body`} class="border-t px-4 py-4" hidden={!shown}>
    {#key epoch}
      {@render children()}
    {/key}

    {#if adjusted.length > 0}
      <div
        class="mt-4 rounded-md border border-sky-500/40 bg-sky-500/10 px-3 py-2 text-sm"
        role="status"
      >
        <p class="font-medium">The server stored some values differently</p>
        <ul class="mt-1 space-y-0.5">
          {#each adjusted as a (a.display)}
            <li>
              <code class="text-xs">{a.display}</code>: you sent {formatConfigValue(a.sent)}, stored
              as {formatConfigValue(a.stored)}
            </li>
          {/each}
        </ul>
        <Button variant="ghost" size="xs" class="mt-1" onclick={() => (adjusted = [])}>
          Dismiss
        </Button>
      </div>
    {/if}

    {#if count > 0 || invalid}
      <div class="mt-4 border-t pt-3">
        {#if count > 0}
          <p class="text-sm font-medium">Changes to save</p>
          <ul class="mt-1 space-y-0.5 text-sm" aria-label={`Pending changes in ${title}`}>
            {#each changes as c (c.display)}
              <li>
                <code class="text-xs">{c.display}</code>:
                <span class="text-muted-foreground">{formatConfigValue(c.from)}</span>
                <span aria-hidden="true"> &rarr; </span><span class="sr-only"> becomes </span>
                <span class="font-medium">{formatConfigValue(c.to)}</span>
              </li>
            {/each}
            {#each extraChanges?.lines ?? [] as line (line)}
              <li>{line}</li>
            {/each}
          </ul>
        {/if}
        {#if note && count > 0}
          <p class="text-muted-foreground mt-2 text-xs">{note}</p>
        {/if}
        {#if invalid}
          <p class="text-destructive mt-2 text-xs">Fix the highlighted fields before saving.</p>
        {/if}
        {#if save.isError}
          <InlineError class="mt-2" message={edgeErrorMessage(save.error)} />
        {/if}
        <div class="mt-3 flex flex-wrap gap-2">
          <Button disabled={count === 0 || invalid || save.isPending} onclick={() => save.mutate()}>
            {save.isPending ? 'Saving…' : 'Save changes'}
          </Button>
          <Button variant="outline" disabled={save.isPending} onclick={discard}>
            Discard changes
          </Button>
        </div>
      </div>
    {/if}
  </div>
</section>
