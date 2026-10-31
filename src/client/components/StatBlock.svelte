<script lang="ts">
  import type { Snippet } from 'svelte';

  /**
   * A single labeled statistic: a quiet label line, the value/content as a
   * snippet so callers can render anything from a large number to a progress
   * bar, and an optional hint line below.
   */
  interface Props {
    label: string;
    hint?: string;
    children?: Snippet;
  }
  let { label, hint, children }: Props = $props();
</script>

<div class="space-y-1.5">
  <p class="text-sm text-muted-foreground">{label}</p>
  {#if children}
    {@render children()}
  {/if}
  {#if hint}
    <p class="text-sm text-muted-foreground tabular-nums">{hint}</p>
  {/if}
</div>
