<script lang="ts">
  /**
   * The "Technical details" fold of a node's page: closed by default, its
   * content mounted only while open (the origin page's tabs poll). Opened by
   * its button, by the section bar, or by an address that names
   * `?section=details` or a tab, an edge or a rotation.
   *
   * Props:
   *   open: boolean
   *   onToggle: () => void
   *   id: string                the section's element id (the section bar scrolls to it)
   *   children: Snippet
   */
  import type { Snippet } from 'svelte';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import { cn } from '@client/lib/utils';

  interface Props {
    open: boolean;
    onToggle: () => void;
    id: string;
    children: Snippet;
  }
  let { open, onToggle, id, children }: Props = $props();
  const uid = $props.id();
</script>

<section {id} class="scroll-mt-16 border-t pt-6" aria-labelledby={`${uid}-title`}>
  <h2 id={`${uid}-title`} class="text-base font-semibold">
    <button
      type="button"
      class="focus-visible:ring-ring/50 inline-flex min-h-11 items-center gap-2 rounded-sm outline-none focus-visible:ring-3"
      aria-expanded={open}
      aria-controls={`${uid}-body`}
      onclick={onToggle}
    >
      Technical details
      <ChevronDown
        class={cn('size-4 transition-transform', open ? 'rotate-180' : '')}
        aria-hidden="true"
      />
    </button>
  </h2>
  {#if !open}
    <p class="text-muted-foreground text-sm">
      Origin overrides, listeners, every edge and its actions, rotations, probes, the Hosts plan and
      the delivery preview.
    </p>
  {/if}
  <div id={`${uid}-body`} hidden={!open} class="mt-4">
    {#if open}{@render children()}{/if}
  </div>
</section>
