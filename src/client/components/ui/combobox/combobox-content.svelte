<script lang="ts">
  import { Combobox as ComboboxPrimitive } from 'bits-ui';
  import { cn, type WithoutChild } from '@client/lib/utils.js';

  let {
    ref = $bindable(null),
    class: className,
    sideOffset = 4,
    children,
    ...restProps
  }: WithoutChild<ComboboxPrimitive.ContentProps> = $props();
</script>

<ComboboxPrimitive.Portal>
  <ComboboxPrimitive.Content
    bind:ref
    {sideOffset}
    data-slot="combobox-content"
    class={cn(
      'bg-popover text-popover-foreground data-open:animate-in data-closed:animate-out data-closed:fade-out-0 data-open:fade-in-0 data-closed:zoom-out-95 data-open:zoom-in-95 ring-foreground/10 relative isolate z-50 max-h-72 min-w-(--bits-combobox-anchor-width) overflow-x-hidden overflow-y-auto rounded-lg p-1 shadow-md ring-1 duration-100',
      className,
    )}
    {...restProps}
  >
    <ComboboxPrimitive.Viewport>
      {@render children?.()}
    </ComboboxPrimitive.Viewport>
  </ComboboxPrimitive.Content>
</ComboboxPrimitive.Portal>
