<script lang="ts">
  import { DropdownMenu as DropdownMenuPrimitive } from 'bits-ui';
  import { cn, type WithoutChildrenOrChild } from '@client/lib/utils.js';
  import type { ComponentProps, Snippet } from 'svelte';

  let {
    ref = $bindable(null),
    sideOffset = 4,
    align = 'end',
    portalProps,
    class: className,
    children,
    ...restProps
  }: WithoutChildrenOrChild<DropdownMenuPrimitive.ContentProps> & {
    portalProps?: ComponentProps<typeof DropdownMenuPrimitive.Portal>;
    children?: Snippet;
  } = $props();
</script>

<DropdownMenuPrimitive.Portal {...portalProps}>
  <DropdownMenuPrimitive.Content
    bind:ref
    data-slot="dropdown-menu-content"
    {sideOffset}
    {align}
    class={cn(
      'bg-popover text-popover-foreground data-open:animate-in data-closed:animate-out data-closed:fade-out-0 data-open:fade-in-0 data-closed:zoom-out-95 data-open:zoom-in-95 ring-foreground/10 z-50 min-w-40 overflow-hidden rounded-lg p-1 shadow-md ring-1 duration-100 outline-none',
      className,
    )}
    {...restProps}
  >
    {@render children?.()}
  </DropdownMenuPrimitive.Content>
</DropdownMenuPrimitive.Portal>
