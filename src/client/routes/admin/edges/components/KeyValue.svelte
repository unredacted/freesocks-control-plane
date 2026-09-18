<script lang="ts">
  /**
   * A titled definition-list section (label / value rows) with copy buttons.
   *
   * Props:
   *   rows: KeyValueRow[]     { label, value, copy?, mono?, tone?, hint? }  (lib/types.ts)
   *   title?: string          section heading (h3)
   *   description?: string
   *   columns?: 1 | 2         grid columns from the `sm` breakpoint (default 2)
   *   hideEmpty?: boolean     drop rows whose value is null / undefined / '' (default false: a dash)
   *   actions?: Snippet       right of the heading
   *   class?: string
   */
  import type { Snippet } from 'svelte';
  import { Badge } from '@client/components/ui/badge';
  import { cn } from '@client/lib/utils';
  import CopyButton from './CopyButton.svelte';
  import { displayValue } from '../lib/format';
  import type { KeyValueRow } from '../lib/types';

  interface Props {
    rows: KeyValueRow[];
    title?: string;
    description?: string;
    columns?: 1 | 2;
    hideEmpty?: boolean;
    actions?: Snippet;
    class?: string;
  }
  let {
    rows,
    title,
    description,
    columns = 2,
    hideEmpty = false,
    actions,
    class: className,
  }: Props = $props();

  const shown = $derived(
    rows
      .map((r) => ({ ...r, text: displayValue(r.value) }))
      .filter((r) => !hideEmpty || r.text !== ''),
  );
</script>

<section class={cn('space-y-2', className)}>
  {#if title || actions}
    <div class="flex items-center justify-between gap-2">
      <div>
        {#if title}<h3 class="text-sm font-semibold">{title}</h3>{/if}
        {#if description}<p class="text-muted-foreground text-xs">{description}</p>{/if}
      </div>
      {#if actions}<div class="flex items-center gap-1.5">{@render actions()}</div>{/if}
    </div>
  {/if}
  {#if shown.length === 0}
    <p class="text-muted-foreground text-sm">Nothing recorded.</p>
  {:else}
    <dl class={cn('grid gap-x-6 gap-y-2 text-sm', columns === 2 && 'sm:grid-cols-2')}>
      {#each shown as row (row.label)}
        <div class="min-w-0">
          <dt class="text-muted-foreground text-xs">{row.label}</dt>
          <dd class="flex min-w-0 items-center gap-1">
            {#if row.text === ''}
              <span class="text-muted-foreground" aria-label="Not set">-</span>
            {:else if row.tone}
              <Badge variant={row.tone}>{row.text}</Badge>
            {:else}
              <span class={cn('min-w-0 break-words', row.mono && 'font-mono text-xs')}>
                {row.text}
              </span>
            {/if}
            {#if row.copy && row.text !== ''}
              <CopyButton value={row.text} label={`Copy ${row.label.toLowerCase()}`} />
            {/if}
          </dd>
          {#if row.hint}<p class="text-muted-foreground text-xs">{row.hint}</p>{/if}
        </div>
      {/each}
    </dl>
  {/if}
</section>
