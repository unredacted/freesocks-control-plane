<script lang="ts">
  /**
   * Vertical steps with status icons. The selected step can render a body under
   * its title (the `children` snippet receives the step). Steps are buttons when
   * `onSelect` is given, plain rows otherwise.
   *
   * Props:
   *   steps: StepperStep[]                  { id, title, description?, status, note? }  (lib/types.ts)
   *   current?: string | null               id of the selected step
   *   onSelect?: (id: string) => void
   *   canSelect?: (step: StepperStep) => boolean   default: every step
   *   children?: Snippet<[StepperStep]>     body of the CURRENT step
   *   label?: string                        accessible name of the list (default 'Steps')
   *   class?: string
   */
  import type { Snippet } from 'svelte';
  import Check from '@lucide/svelte/icons/check';
  import CircleDot from '@lucide/svelte/icons/circle-dot';
  import TriangleAlert from '@lucide/svelte/icons/triangle-alert';
  import Minus from '@lucide/svelte/icons/minus';
  import { cn } from '@client/lib/utils';
  import { SETUP_STATUS_LABELS } from '@client/lib/edgeCodes';
  import type { StepperStep } from '../lib/types';

  interface Props {
    steps: StepperStep[];
    current?: string | null;
    onSelect?: (id: string) => void;
    canSelect?: (step: StepperStep) => boolean;
    children?: Snippet<[StepperStep]>;
    label?: string;
    class?: string;
  }
  let {
    steps,
    current = null,
    onSelect,
    canSelect,
    children,
    label = 'Steps',
    class: className,
  }: Props = $props();

  const ICON_TONE: Record<StepperStep['status'], string> = {
    done: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/40',
    ready: 'bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/40',
    blocked: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/40',
    skipped: 'bg-muted text-muted-foreground border-border',
  };
</script>

{#snippet head(step: StepperStep, index: number)}
  <span class="flex min-w-0 flex-1 flex-col text-start">
    <span class="flex flex-wrap items-baseline gap-x-2">
      <span class={cn('text-sm font-medium', step.status === 'skipped' && 'text-muted-foreground')}>
        <span class="sr-only">Step {index + 1}: </span>{step.title}
      </span>
      <span class="text-muted-foreground text-xs">
        {SETUP_STATUS_LABELS[step.status]}{step.note ? `, ${step.note}` : ''}
      </span>
    </span>
    {#if step.description}
      <span class="text-muted-foreground text-xs">{step.description}</span>
    {/if}
  </span>
{/snippet}

<ol class={cn('relative', className)} aria-label={label}>
  {#each steps as step, i (step.id)}
    {@const selected = step.id === current}
    {@const last = i === steps.length - 1}
    <li class="relative flex gap-3 pb-4" aria-current={selected ? 'step' : undefined}>
      {#if !last}
        <span
          class="bg-border absolute start-3 top-7 bottom-0 w-px -translate-x-1/2"
          aria-hidden="true"
        ></span>
      {/if}
      <span
        class={cn(
          'relative z-10 mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full border',
          ICON_TONE[step.status],
          selected && 'ring-ring/50 ring-2',
        )}
        aria-hidden="true"
      >
        {#if step.status === 'done'}
          <Check class="size-3.5" />
        {:else if step.status === 'ready'}
          <CircleDot class="size-3.5" />
        {:else if step.status === 'blocked'}
          <TriangleAlert class="size-3.5" />
        {:else}
          <Minus class="size-3.5" />
        {/if}
      </span>
      <div class="min-w-0 flex-1">
        {#if onSelect && (canSelect ? canSelect(step) : true)}
          <button
            type="button"
            class={cn(
              'hover:bg-accent/50 focus-visible:ring-ring/50 -mx-1.5 flex w-full rounded-md px-1.5 py-0.5 outline-none focus-visible:ring-3',
              selected && 'bg-accent/60',
            )}
            aria-expanded={children ? selected : undefined}
            onclick={() => onSelect(step.id)}
          >
            {@render head(step, i)}
          </button>
        {:else}
          <div class="flex py-0.5">{@render head(step, i)}</div>
        {/if}
        {#if selected && children}
          <div class="mt-3">{@render children(step)}</div>
        {/if}
      </div>
    </li>
  {/each}
</ol>
