<script lang="ts" module>
  export type IssueSeverity = 'critical' | 'warning' | 'info';
</script>

<script lang="ts">
  /**
   * One compact issue line, the shape every Action needed list draws: a
   * severity icon, the title (with a count when it stands for several items
   * and who it is about), at most ONE short line under it, when it started,
   * and its button. Everything longer (why, what to do, the raw facts, the
   * items of a group) sits behind the row's disclosure, closed by default.
   * Meant to sit in a `<ul class="divide-y rounded-lg border">` (IssueList).
   *
   * Props:
   *   severity: IssueSeverity | null   null: not a problem (a setting or an option): no icon
   *   title: string
   *   subject?: string | null       who or what it is about (muted, one line, truncated)
   *   count?: number                items behind a grouped row (shown from 2)
   *   line?: string | null          one short sentence or fact line
   *   since?: string | null         ISO time it started
   *   details?: Snippet             the hidden part; no toggle without it
   *   action?: Snippet              the row's button
   *   open?: boolean                (bindable) the details are shown
   *   nested?: boolean              a row inside a group's details: no icon column
   */
  import type { Snippet } from 'svelte';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import OctagonAlert from '@lucide/svelte/icons/octagon-alert';
  import TriangleAlert from '@lucide/svelte/icons/triangle-alert';
  import Info from '@lucide/svelte/icons/info';
  import { Badge } from '@client/components/ui/badge';
  import { cn } from '@client/lib/utils';
  import { relativeTime } from '../lib/time';

  interface Props {
    severity: IssueSeverity | null;
    title: string;
    subject?: string | null;
    count?: number;
    line?: string | null;
    since?: string | null;
    details?: Snippet;
    action?: Snippet;
    open?: boolean;
    nested?: boolean;
  }
  let {
    severity,
    title,
    subject = null,
    count,
    line = null,
    since = null,
    details,
    action,
    open = $bindable(false),
    nested = false,
  }: Props = $props();

  const uid = $props.id();
  const ICON = { critical: OctagonAlert, warning: TriangleAlert, info: Info } as const;
  const TONE = {
    critical: 'text-destructive',
    warning: 'text-amber-600 dark:text-amber-400',
    info: 'text-sky-600 dark:text-sky-400',
  } as const;
  const WORD = { critical: 'Critical', warning: 'Warning', info: 'Info' } as const;
  const Icon = $derived(severity ? ICON[severity] : null);
</script>

{#snippet text()}
  <span class="flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-0.5">
    <span class="text-sm font-medium">{title}</span>
    {#if count !== undefined && count > 1}
      <Badge variant="muted" class="tabular-nums">{count}</Badge>
    {/if}
    {#if subject}
      <span class="text-muted-foreground min-w-0 truncate text-sm" title={subject}>{subject}</span>
    {/if}
  </span>
  {#if line}
    <span class="text-muted-foreground mt-0.5 block text-sm">{line}</span>
  {/if}
{/snippet}

<div class={cn('flex items-start gap-3 py-2.5', nested ? 'px-3' : 'px-3 sm:px-4')}>
  {#if !nested && severity && Icon}
    <Icon class={cn('mt-0.5 size-4 shrink-0', TONE[severity])} aria-hidden="true" />
    <span class="sr-only">{WORD[severity]}:</span>
  {/if}
  {#if details}
    <!-- The text opens the details too, for a mouse; the chevron is the control. -->
    <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
    <div class="min-w-0 flex-1 cursor-pointer" onclick={() => (open = !open)}>
      {@render text()}
    </div>
  {:else}
    <div class="min-w-0 flex-1">{@render text()}</div>
  {/if}
  {#if since}
    <time
      class="text-muted-foreground mt-0.5 hidden shrink-0 text-xs whitespace-nowrap tabular-nums sm:block"
      datetime={since}
      title={new Date(since).toLocaleString()}
    >
      {relativeTime(since)}
    </time>
  {/if}
  {#if action}
    <div class="-my-0.5 shrink-0">{@render action()}</div>
  {/if}
  {#if details}
    <button
      type="button"
      class="text-muted-foreground hover:text-foreground hover:bg-accent focus-visible:ring-ring/50 -my-1 inline-flex size-7 shrink-0 items-center justify-center rounded-md outline-none focus-visible:ring-3"
      aria-expanded={open}
      aria-controls={`${uid}-details`}
      aria-label={`${open ? 'Hide' : 'Show'} details: ${title}`}
      onclick={() => (open = !open)}
    >
      <ChevronDown
        class={cn('size-4 transition-transform', open && 'rotate-180')}
        aria-hidden="true"
      />
    </button>
  {:else if !nested}
    <!-- Keeps the buttons of rows with and without details in one column. -->
    <span class="size-7 shrink-0" aria-hidden="true"></span>
  {/if}
</div>
{#if details && open}
  <div
    id={`${uid}-details`}
    class={cn(
      'text-muted-foreground space-y-1.5 pb-3 text-sm',
      nested ? 'px-3' : !severity ? 'px-3 sm:px-4' : 'ps-10 pe-3 sm:pe-4',
    )}
  >
    {@render details()}
  </div>
{/if}
