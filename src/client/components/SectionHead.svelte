<script lang="ts">
  import type { Component } from 'svelte';

  /**
   * Consistent section header: an optional quiet kicker (letter-spaced
   * microcopy, NO accent bar - the accent color is reserved for actions and
   * live data), a display title, and a one-line description. `divider` draws
   * the hairline that separates this section from the one above it - the
   * design language's primary separator (whitespace + hairlines, not boxes).
   */
  interface Props {
    icon?: Component;
    kicker?: string;
    title: string;
    description?: string;
    divider?: boolean;
  }
  let { icon: Icon, kicker, title, description, divider = false }: Props = $props();
</script>

<div class="space-y-1 {divider ? 'border-t border-border pt-6' : ''}">
  {#if kicker}
    <p class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">{kicker}</p>
  {/if}
  <h2
    class="text-xl font-display font-semibold tracking-tight {Icon
      ? 'flex items-center gap-2'
      : ''}"
  >
    {#if Icon}<Icon class="size-4 text-muted-foreground" aria-hidden="true" />{/if}
    {title}
  </h2>
  {#if description}
    <p class="text-sm text-muted-foreground">{description}</p>
  {/if}
</div>
