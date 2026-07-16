<script lang="ts">
  import type { Component, Snippet } from 'svelte';

  /**
   * A single labeled statistic: the quiet uppercase label row (the instrument
   * discipline - data reads as data), the value/content as a snippet so callers
   * can render anything from a mono number to a progress bar, and an optional
   * hint line below. Used for traffic, expiry, impact numbers, and anywhere a
   * metric needs a calm, consistent frame.
   */
  interface Props {
    icon?: Component;
    label: string;
    hint?: string;
    children?: Snippet;
  }
  let { icon: Icon, label, hint, children }: Props = $props();
</script>

<div class="space-y-1.5">
  <p
    class="flex items-center gap-1.5 text-xs uppercase tracking-wider text-muted-foreground font-semibold"
  >
    {#if Icon}<Icon class="size-3.5" aria-hidden="true" />{/if}
    {label}
  </p>
  {#if children}
    {@render children()}
  {/if}
  {#if hint}
    <p class="text-[11px] text-muted-foreground tabular-nums">{hint}</p>
  {/if}
</div>
