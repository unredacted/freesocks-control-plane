<script lang="ts">
  import { Tooltip as TooltipPrimitive } from 'bits-ui';
  import { cn, type WithoutChildrenOrChild } from '@client/lib/utils.js';
  import type { Snippet } from 'svelte';

  let {
    ref = $bindable(null),
    class: className,
    sideOffset = 4,
    children,
    ...restProps
  }: WithoutChildrenOrChild<TooltipPrimitive.ContentProps> & { children?: Snippet } = $props();
</script>

<TooltipPrimitive.Portal>
  <TooltipPrimitive.Content
    bind:ref
    data-slot="tooltip-content"
    {sideOffset}
    class={cn(
      'bg-foreground text-background data-open:animate-in data-closed:animate-out data-closed:fade-out-0 data-open:fade-in-0 data-closed:zoom-out-95 data-open:zoom-in-95 z-50 max-w-xs rounded-md px-2.5 py-1.5 text-xs text-balance shadow-md',
      className,
    )}
    {...restProps}
  >
    {@render children?.()}
  </TooltipPrimitive.Content>
</TooltipPrimitive.Portal>
