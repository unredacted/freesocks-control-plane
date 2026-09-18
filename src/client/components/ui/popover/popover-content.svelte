<script lang="ts">
  import { Popover as PopoverPrimitive } from 'bits-ui';
  import { cn, type WithoutChildrenOrChild } from '@client/lib/utils.js';
  import type { ComponentProps, Snippet } from 'svelte';

  let {
    ref = $bindable(null),
    class: className,
    sideOffset = 4,
    align = 'start',
    portalProps,
    children,
    ...restProps
  }: WithoutChildrenOrChild<PopoverPrimitive.ContentProps> & {
    portalProps?: ComponentProps<typeof PopoverPrimitive.Portal>;
    children?: Snippet;
  } = $props();
</script>

<PopoverPrimitive.Portal {...portalProps}>
  <PopoverPrimitive.Content
    bind:ref
    data-slot="popover-content"
    {sideOffset}
    {align}
    class={cn(
      'bg-popover text-popover-foreground data-open:animate-in data-closed:animate-out data-closed:fade-out-0 data-open:fade-in-0 data-closed:zoom-out-95 data-open:zoom-in-95 ring-foreground/10 z-50 w-72 rounded-lg p-3 shadow-md ring-1 duration-100 outline-none',
      className,
    )}
    {...restProps}
  >
    {@render children?.()}
  </PopoverPrimitive.Content>
</PopoverPrimitive.Portal>
