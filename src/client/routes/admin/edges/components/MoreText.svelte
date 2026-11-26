<script lang="ts">
  /**
   * Admin copy, one sentence at a time: the first sentence shows, and a small
   * "More" reveals the rest in place (`splitLead`). Text of one sentence shows
   * as it is, with no control. Inline, so it can sit inside a `<p>` or a label.
   *
   * Props:
   *   text: string
   *   class?: string        on the outer span
   */
  import { cn } from '@client/lib/utils';
  import { splitLead } from '@client/lib/splitLead';

  interface Props {
    text: string;
    class?: string;
  }
  let { text, class: className }: Props = $props();

  const parts = $derived(splitLead(text));
  let open = $state(false);
</script>

<span class={className}>
  {parts.lead}{#if parts.rest}
    {#if open}
      {' '}{parts.rest}
    {/if}
    <button
      type="button"
      class={cn(
        'text-muted-foreground hover:text-foreground focus-visible:ring-ring/50 ms-1 rounded-sm text-xs underline underline-offset-2 outline-none focus-visible:ring-3',
      )}
      aria-expanded={open}
      onclick={() => (open = !open)}
    >
      {open ? 'Less' : 'More'}
    </button>
  {/if}
</span>
