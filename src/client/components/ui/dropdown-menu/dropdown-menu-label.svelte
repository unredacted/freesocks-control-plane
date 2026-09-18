<script lang="ts">
  import { DropdownMenu as DropdownMenuPrimitive } from 'bits-ui';
  import { cn } from '@client/lib/utils.js';

  let {
    ref = $bindable(null),
    class: className,
    inset,
    ...restProps
  }: DropdownMenuPrimitive.GroupHeadingProps & { inset?: boolean } = $props();
</script>

<DropdownMenuPrimitive.GroupHeading
  bind:ref
  data-slot="dropdown-menu-label"
  data-inset={inset}
  class={cn('text-muted-foreground px-2 py-1.5 text-xs font-medium data-[inset]:ps-8', className)}
  {...restProps}
/>
